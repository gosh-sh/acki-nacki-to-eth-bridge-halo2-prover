//! Quick diagnostic: compare BOC reconstruction strategies for gql block fields.

use std::collections::HashMap;

use base64::Engine;
use bridge_prover_lib::gql_client::create_client;
use serde_json::Value;
use bridge_parsers::attestation_data_parser::{
    parse_attestation_data_bytes, parse_signature_bytes, parse_signer_entries,
};
use gosh_bls_verification::helpers::{
    compute_agg_pubkey, compute_msg_hash, deserialize_g2_signature, resolve_pubkeys,
    verify_bls_native,
};

fn off_circuit_bls(raw: &[u8], bk: &HashMap<u16, Vec<u8>>) -> bool {
    let sig = deserialize_g2_signature(parse_signature_bytes(raw));
    let entries = parse_signer_entries(raw);
    let att_data = parse_attestation_data_bytes(raw);
    let msg_hash = compute_msg_hash(&att_data[..120.min(att_data.len())]);
    let pks = resolve_pubkeys(&entries, bk);
    let agg_pk = compute_agg_pubkey(&pks);
    verify_bls_native(&sig, &agg_pk, &msg_hash)
}

fn scan_attestations_from(data: &[u8], start: usize, label: &str, bk: &HashMap<u16, Vec<u8>>) {
    let atts = bridge_prover_lib::boc_parser::scan_attestations_in_buffer(data, start);
    if atts.is_empty() {
        println!("  [{label}] no attestations");
        return;
    }
    for att in atts {
        println!(
            "  [{label}] seq={} type={} bls={}",
            att.block_seq_no,
            att.target_type,
            off_circuit_bls(&att.raw_bytes, bk)
        );
    }
}

async fn fetch_raw_block_fields(gql: &bridge_prover_lib::gql_client::GqlClient, seq: u64) -> Value {
    let tid = "00000000000000000000000000000000000000000000000000000000000000000000";
    let q = format!(
        r#"{{ blockchain {{ blockByHeight(thread_id: "{tid}", height: {seq}) {{ data aggregated_signature signature_occurrences }} }} }}"#
    );
    gql.query(&q)
        .await
        .expect("query")
        .pointer("/blockchain/blockByHeight")
        .cloned()
        .expect("block")
}

fn parse_blob(v: &Value) -> Vec<u8> {
    if let Some(arr) = v.as_array() {
        return arr.iter().map(|x| x.as_u64().unwrap() as u8).collect();
    }
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap())
        .unwrap()
}

fn decompress(data_b64: &str) -> Vec<u8> {
    let compressed = base64::engine::general_purpose::STANDARD.decode(data_b64).unwrap();
    zstd::decode_all(compressed.as_slice()).unwrap_or(compressed)
}

#[tokio::test]
async fn gql_boc_reconstruction_strategies() {
    let gql_url = std::env::var("BRIDGE_GQL_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost/graphql".to_string());
    let gql = create_client(&gql_url).expect("gql client");

    let bk = bridge_prover_lib::bk_set_fetcher::load_bk_set_from_config("bk_set.json")
        .or_else(|_| bridge_prover_lib::bk_set_fetcher::load_bk_set_from_config("../bk_set.json"))
        .expect("bk_set.json");

    for seq in [1025u64, 1026] {
        let block = fetch_raw_block_fields(&gql, seq).await;
        let agg = parse_blob(block.get("aggregated_signature").unwrap());
        let occ = parse_blob(block.get("signature_occurrences").unwrap());
        let block_data = decompress(block.get("data").and_then(|v| v.as_str()).unwrap());

        let mut proper = agg.clone();
        let occ_map: HashMap<u16, u16> = bincode::deserialize(&occ).expect("occ map");
        let mut occ_vec: Vec<(u16, u16)> = occ_map.into_iter().collect();
        occ_vec.sort_by_key(|(k, _)| *k);
        proper.extend(bincode::serialize(&occ_vec).expect("occ vec"));
        proper.extend_from_slice(&block_data);

        let (_hash, boc) = gql.query_block_boc_by_seq_no(seq).await.expect("fetch boc");
        let skip = if boc.len() >= 208 {
            200 + 8 + (u64::from_le_bytes(boc[200..208].try_into().unwrap()) as usize) * 4
        } else {
            0
        };
        println!(
            "\n=== block seq={seq} data={} boc={} skip={} proper={} tail_match={} ===",
            block_data.len(),
            boc.len(),
            skip,
            proper.len(),
            boc.get(skip..skip + 16.min(block_data.len()))
                == block_data.get(0..16.min(block_data.len()))
        );

        scan_attestations_from(&block_data, 0, "block_data_only", &bk);
        scan_attestations_from(&proper, 0, "proper_envelope", &bk);
        if skip < boc.len() {
            scan_attestations_from(&boc, skip, "boc_after_skip", &bk);
        }

        let atts = bridge_prover_lib::boc_parser::extract_attestations_from_boc(&boc)
            .unwrap_or_default();
        println!("extract_attestations_from_boc: {} attestation(s)", atts.len());
        for att in &atts {
            let bls = off_circuit_bls(&att.raw_bytes, &bk);
            println!(
                "  seq_no={} type={} raw={} bls={} block_id={} env_hash={}",
                att.block_seq_no,
                att.target_type,
                att.raw_bytes.len(),
                bls,
                hex::encode(att.block_id),
                hex::encode(att.envelope_hash),
            );
        }
        if let Some(att) = atts.iter().find(|a| a.block_seq_no == 1024 && a.target_type == 0) {
            println!(
                "  primary for 1024: bls={} raw_head={}",
                off_circuit_bls(&att.raw_bytes, &bk),
                hex::encode(&att.raw_bytes[..64.min(att.raw_bytes.len())])
            );
        }
    }
}
