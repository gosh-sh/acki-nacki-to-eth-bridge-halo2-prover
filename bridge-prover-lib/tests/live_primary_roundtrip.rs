//! Live round-trip: fetch attestation via gql `data` reconstruction, prove, verify.
//! Step-1 diagnostic: off-circuit BLS + optional MockProver (`BRIDGE_MOCK_PROVE=1`).

use std::collections::HashMap;
use std::path::Path;

use bridge_prover_lib::attestation_fetcher::fetch_attestation_for_block;
use bridge_prover_lib::bk_set_fetcher::{fetch_bk_set, load_bk_set_from_config};
use bridge_prover_lib::gql_client::create_client;
use bridge_prover_lib::keys::KeyManager;
use bridge_prover_lib::poseidon::compute_bk_set_poseidon;
use bridge_prover_lib::prover::generate_primary_proof;
use bridge_prover_lib::verifier::verify_primary_proof;
use bridge_parsers::attestation_data_parser::{
    parse_attestation_data_bytes, parse_signature_bytes, parse_signer_entries,
};
use gosh_bls_verification::helpers::{
    compute_agg_pubkey, compute_msg_hash, deserialize_g2_signature, resolve_pubkeys,
    verify_bls_native,
};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

fn off_circuit_bls_ok(raw_bytes: &[u8], bk_set: &HashMap<u16, Vec<u8>>) -> bool {
    let sig_bytes = parse_signature_bytes(raw_bytes);
    let entries = parse_signer_entries(raw_bytes);
    let att_data = parse_attestation_data_bytes(raw_bytes);
    let signature = deserialize_g2_signature(sig_bytes);
    let msg_hash = compute_msg_hash(&att_data[..120]);
    let pks = resolve_pubkeys(&entries, bk_set);
    let agg_pk = compute_agg_pubkey(&pks);
    verify_bls_native(&signature, &agg_pk, &msg_hash)
}

fn print_bk_set_summary(label: &str, bk_set: &HashMap<u16, Vec<u8>>) {
    let (commitment, _) = compute_bk_set_poseidon(bk_set);
    println!(
        "BK set [{label}]: {} signers, commitment={}",
        bk_set.len(),
        bridge_prover_lib::ipc::fr_to_hex(&commitment)
    );
}

fn bk_set_path() -> Option<&'static str> {
    for p in ["bk_set.json", "../bk_set.json"] {
        if Path::new(p).exists() {
            return Some(p);
        }
    }
    None
}

fn params_dir() -> &'static str {
    if Path::new("params").exists() {
        "params"
    } else {
        "../params"
    }
}

#[tokio::test]
async fn live_primary_attestation_prove_verify_roundtrip() {
    let Some(bk_path) = bk_set_path() else {
        eprintln!("skip: bk_set.json missing");
        return;
    };

    let gql_url = std::env::var("BRIDGE_GQL_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost/graphql".to_string());
    let gql = match create_client(&gql_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip: gql unavailable: {e}");
            return;
        }
    };

    let att = match fetch_attestation_for_block(&gql, 1024).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("skip: attestation fetch failed: {e}");
            return;
        }
    };

    println!(
        "attestation seq={} block_id={} envelope_hash={} raw_bytes={} signers={:?}",
        att.block_seq_no,
        hex::encode(att.block_id),
        hex::encode(att.envelope_hash),
        att.raw_bytes.len(),
        att.signature_occurrences
    );

    let file_bk_set: HashMap<u16, Vec<u8>> = load_bk_set_from_config(bk_path).expect("bk set");
    print_bk_set_summary("file", &file_bk_set);
    let file_bls = off_circuit_bls_ok(&att.raw_bytes, &file_bk_set);
    println!("off-circuit BLS [file bk_set]: {file_bls}");

    let gql_bk_set = fetch_bk_set(&gql).await.ok();
    if let Some(ref gql_bk) = gql_bk_set {
        print_bk_set_summary("gql", gql_bk);
        let gql_bls = off_circuit_bls_ok(&att.raw_bytes, gql_bk);
        println!("off-circuit BLS [gql bk_set]: {gql_bls}");
    } else {
        println!("off-circuit BLS [gql bk_set]: skipped (fetch_bk_set failed)");
    }

    let bk_set = if let Some(ref gql_bk) = gql_bk_set {
        if off_circuit_bls_ok(&att.raw_bytes, gql_bk) {
            println!("using gql bk_set for prove (BLS passed)");
            gql_bk.clone()
        } else if file_bls {
            println!("using file bk_set for prove (BLS passed)");
            file_bk_set
        } else {
            println!("using file bk_set for prove (neither BLS passed — diagnostic only)");
            file_bk_set
        }
    } else if file_bls {
        file_bk_set
    } else {
        file_bk_set
    };

    let mut key_manager = KeyManager::new(Path::new(params_dir()));
    key_manager
        .ensure_primary_keys(&bk_set)
        .expect("primary keys");
    key_manager.load_primary_pk().expect("load pk");

    let last_seen = 512u32;
    let out = generate_primary_proof(
        &key_manager,
        &att.raw_bytes,
        &bk_set,
        last_seen,
    )
    .expect("prove");

    let instances = vec![
        out.block_id_fr,
        out.bk_set_commitment_fr,
        Fr::from(out.block_seq_no as u64),
        Fr::from(last_seen as u64),
    ];

    println!(
        "instances: block_id_fr={} bk_set={} seq_no_fr={} last_seen_fr={}",
        bridge_prover_lib::ipc::fr_to_hex(&instances[0]),
        bridge_prover_lib::ipc::fr_to_hex(&instances[1]),
        bridge_prover_lib::ipc::fr_to_hex(&instances[2]),
        bridge_prover_lib::ipc::fr_to_hex(&instances[3]),
    );
    println!(
        "envelope block_id bytes={} circuit block_id_fr={}",
        hex::encode(att.block_id),
        bridge_prover_lib::ipc::fr_to_hex(&out.block_id_fr),
    );

    let ok = verify_primary_proof(&key_manager, &out.proof_bytes, &instances);
    println!("verify_primary_proof: {ok}");

    if std::env::var("BRIDGE_DIAG_ONLY").ok().as_deref() == Some("1") {
        println!("BRIDGE_DIAG_ONLY=1: skipping assert");
        return;
    }

    assert!(
        file_bls || gql_bk_set.as_ref().is_some_and(|g| off_circuit_bls_ok(&att.raw_bytes, g)),
        "off-circuit BLS must pass with file or gql bk_set (attestation bytes or BK set stale)"
    );
    assert!(ok, "primary proof must verify against freshly fetched attestation");
}
