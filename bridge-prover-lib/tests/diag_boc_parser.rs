//! Diagnostic: capture a live attestation by two independent paths and diff them.
//!
//! Path A (byte-scan): `boc_parser::extract_attestations_from_boc` on raw BOC bytes.
//! Path B (typed): `bincode::deserialize::<Envelope<AckiNackiBlock>>` → walk
//!   common_section.block_attestations → `bincode::serialize` the matching envelope.
//!
//! If A == B, the byte-scanner is faithful to the wire format. If A != B,
//! the first divergence pinpoints the boc_parser bug.
//!
//! Also writes `/tmp/live_attestation.hex` (path A) so the existing
//! `live_attestation_test` can be run to off-circuit verify the BLS signature.
//!
//! Gated by env var `BRIDGE_DIAG_RUN=1` so it doesn't run in regular `cargo test`.
//! Requires a running node at the URL in `BRIDGE_NODE_URL` (default http://localhost).
//! Target seq_no defaults to 8; override with `BRIDGE_DIAG_SEQNO`.

use std::collections::HashMap;

use bridge_prover_lib::boc_parser;
use bridge_prover_lib::bk_set_fetcher;
use bridge_prover_lib::gql_client;
use node_block_client::BLSSignedEnvelope;
use node_block_client::types::{BlockKeeperSetChange, SignerIndex};

fn enabled() -> bool {
    std::env::var("BRIDGE_DIAG_RUN").ok().as_deref() == Some("1")
}

fn target_seqno() -> u32 {
    std::env::var("BRIDGE_DIAG_SEQNO")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
}

fn node_url() -> String {
    std::env::var("BRIDGE_NODE_URL").unwrap_or_else(|_| "http://localhost".to_string())
}

#[tokio::test]
async fn diag_boc_parser_vs_typed_deserialize() {
    if !enabled() {
        eprintln!("Skipping: set BRIDGE_DIAG_RUN=1 to run.");
        return;
    }

    let target = target_seqno();
    let url = node_url();
    let gql = gql_client::create_client(&url).expect("create client");

    // Try seq=target+1, +2, +3 to find the block carrying the attestation.
    let mut found = None;
    for delta in 1u32..=3 {
        let source_seq = (target + delta) as u64;
        let boc = match gql.query_block_boc_by_seq_no(source_seq).await {
            Ok((_h, b)) => b,
            Err(e) => {
                eprintln!("seq={} not available: {}", source_seq, e);
                continue;
            }
        };
        let envelope = match gql.query_block_envelope(source_seq).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("typed deserialize at seq={} failed: {}", source_seq, e);
                continue;
            }
        };
        found = Some((source_seq, boc, envelope));
        break;
    }

    let (source_seq, boc, envelope) =
        found.expect("could not fetch any of target+1..target+3");
    println!(
        "source block seq={} (carries attestation for target seq={})",
        source_seq, target
    );
    println!("BOC length = {} bytes", boc.len());

    // ---- Path A: byte-scanner.
    let parsed = boc_parser::extract_attestations_from_boc(&boc)
        .expect("boc_parser failed");
    println!("path A (byte-scan): {} attestation(s) found", parsed.len());
    let a = parsed
        .iter()
        .find(|p| p.block_seq_no == target)
        .unwrap_or_else(|| panic!("path A: no attestation for seq={}", target));
    println!(
        "  path A match: seq={}, type={}, signers={:?}, raw_bytes={}B",
        a.block_seq_no,
        if a.target_type == 0 { "Primary" } else { "Fallback" },
        a.signature_occurrences,
        a.raw_bytes.len(),
    );

    // ---- Path B: typed deserialize.
    let ackiblock = envelope.data();
    let common = ackiblock.common_section();
    let block_atts = common.block_attestations();
    println!("path B (typed): {} attestation(s) in common_section", block_atts.len());
    let b_env = block_atts
        .iter()
        .find(|e| u32::from(*e.data().block_seq_no()) == target)
        .unwrap_or_else(|| panic!("path B: no attestation for seq={}", target));
    let b_bytes = bincode::serialize(b_env).expect("re-serialize typed envelope");
    let b_data = b_env.data();
    println!(
        "  path B match: seq={}, type={:?}, bincode size={}B",
        u32::from(*b_data.block_seq_no()),
        b_data.target_type(),
        b_bytes.len(),
    );

    // ---- Compare.
    if a.raw_bytes == b_bytes {
        println!("✓ PATH A == PATH B (byte-scanner is faithful)");
    } else {
        println!("✗ PATH A != PATH B");
        println!(
            "  lengths: A={} bytes, B={} bytes",
            a.raw_bytes.len(),
            b_bytes.len()
        );
        let n = a.raw_bytes.len().min(b_bytes.len());
        let mut first_diff: Option<usize> = None;
        for i in 0..n {
            if a.raw_bytes[i] != b_bytes[i] {
                first_diff = Some(i);
                break;
            }
        }
        match first_diff {
            None if a.raw_bytes.len() != b_bytes.len() => {
                println!(
                    "  first differs in length at offset {} (one ran out)",
                    n
                );
            }
            Some(i) => {
                println!("  first differing byte at offset {}", i);
                let lo = i.saturating_sub(8);
                let hi = (i + 24).min(n);
                println!("    A[{}..{}] = {}", lo, hi, hex::encode(&a.raw_bytes[lo..hi]));
                println!("    B[{}..{}] = {}", lo, hi, hex::encode(&b_bytes[lo..hi]));
            }
            None => {}
        }
    }

    // ---- Path C: reconstruct live bk_set by walking blocks (block_keeper_set_changes
    //              in CommonSection). GraphQL bkSetUpdates is empty on this node.
    println!("\n--- Path C: live bk_set + off-circuit BLS verify ---");
    let mut live_bk_set: HashMap<u16, Vec<u8>> = HashMap::new();
    let max_walk: u64 = std::env::var("BRIDGE_DIAG_WALK_MAX")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    for seq in 0u64..=max_walk {
        let env = match gql.query_block_envelope(seq).await {
            Ok(e) => e,
            Err(e) => { eprintln!("  walk seq={}: {}", seq, e); continue; }
        };
        let cs = env.data().common_section();
        for ch in cs.block_keeper_set_changes() {
            match ch {
                BlockKeeperSetChange::BlockKeeperAdded((idx, data)) => {
                    let pk_bytes = data.pubkey.as_ref().to_bytes().to_vec();
                    println!("  seq={} added signer {} pk={}...",
                        seq, idx, hex::encode(&pk_bytes[..8]));
                    live_bk_set.insert(*idx as u16, pk_bytes);
                }
                BlockKeeperSetChange::BlockKeeperRemoved((idx, _)) => {
                    println!("  seq={} removed signer {}", seq, idx);
                    live_bk_set.remove(&(*idx as u16));
                }
                BlockKeeperSetChange::FutureBlockKeeperAdded((idx, _)) => {
                    println!("  seq={} future-added signer {} (not activated)", seq, idx);
                }
                #[cfg(feature = "protocol_version_hash_in_block")]
                BlockKeeperSetChange::BlockKeeperChangedVersion(_) => {}
            }
        }
        let _: SignerIndex = 0; // silence unused-import warning if no changes seen
    }
    println!("live bk_set: {} signers, indices={:?}",
        live_bk_set.len(), {
            let mut k: Vec<_> = live_bk_set.keys().collect();
            k.sort();
            k
        }
    );
    // Compare with the on-disk file.
    let file_bk_set = bk_set_fetcher::load_bk_set_from_config(
        "/Users/alinat/HALO2_TVM_EXPERIMENTS/acki-nacki-to-eth-bridge-halo2-prover/bk_set.json",
    )
    .expect("load file bk_set");
    let mut diffs = 0usize;
    for (idx, live_pk) in &live_bk_set {
        match file_bk_set.get(idx) {
            None => {
                println!("  signer {}: only in LIVE (file missing)", idx);
                diffs += 1;
            }
            Some(file_pk) if file_pk != live_pk => {
                println!(
                    "  signer {}: DIFFERS\n    live={}\n    file={}",
                    idx,
                    hex::encode(live_pk),
                    hex::encode(file_pk)
                );
                diffs += 1;
            }
            _ => {}
        }
    }
    for idx in file_bk_set.keys() {
        if !live_bk_set.contains_key(idx) {
            println!("  signer {}: only in FILE (live missing)", idx);
            diffs += 1;
        }
    }
    println!("bk_set diffs vs file: {}", diffs);

    // Confirm message slice equality: att_data[..120] vs bincode(b_env.data()).
    let typed_msg = bincode::serialize(b_env.data()).expect("serialize AttestationData");
    println!(
        "typed bincode(AttestationData) = {}B, equals att_data[..120]? {}",
        typed_msg.len(),
        {
            let att_data_chk = bridge_parsers::attestation_data_parser::parse_attestation_data_bytes(&a.raw_bytes);
            typed_msg.as_slice() == &att_data_chk[..120]
        }
    );

    // Off-circuit BLS verify with live bk_set.
    let sig_bytes = bridge_parsers::attestation_data_parser::parse_signature_bytes(&a.raw_bytes);
    let entries = bridge_parsers::attestation_data_parser::parse_signer_entries(&a.raw_bytes);
    let att_data = bridge_parsers::attestation_data_parser::parse_attestation_data_bytes(&a.raw_bytes);
    let msg = &att_data[..120];
    let signature = gosh_bls_verification::helpers::deserialize_g2_signature(sig_bytes);
    let msg_hash = gosh_bls_verification::helpers::compute_msg_hash(msg);

    if !live_bk_set.is_empty() && entries.iter().all(|(i, _)| live_bk_set.contains_key(i)) {
        let pubkeys_live = gosh_bls_verification::helpers::resolve_pubkeys(&entries, &live_bk_set);
        let agg_live = gosh_bls_verification::helpers::compute_agg_pubkey(&pubkeys_live);
        let ok_live = gosh_bls_verification::helpers::verify_bls_native(&signature, &agg_live, &msg_hash);
        println!("BLS verify with LIVE bk_set: {}", if ok_live { "PASS" } else { "FAIL" });
    } else {
        println!("BLS verify with LIVE bk_set: SKIPPED (live bk_set incomplete: {} signers, signers needed={:?})",
            live_bk_set.len(),
            entries.iter().map(|(i,_)| *i).collect::<Vec<_>>());
    }

    let pubkeys_file = gosh_bls_verification::helpers::resolve_pubkeys(&entries, &file_bk_set);
    let agg_file = gosh_bls_verification::helpers::compute_agg_pubkey(&pubkeys_file);
    let ok_file = gosh_bls_verification::helpers::verify_bls_native(&signature, &agg_file, &msg_hash);
    println!("BLS verify with FILE bk_set: {}", if ok_file { "PASS" } else { "FAIL" });

    // Dump live bk_set for downstream tests.
    let live_json: std::collections::HashMap<String, String> = live_bk_set
        .iter()
        .map(|(k, v)| (k.to_string(), hex::encode(v)))
        .collect();
    std::fs::write(
        "/tmp/bk_set_live.json",
        serde_json::to_string_pretty(&live_json).unwrap(),
    )
    .expect("write /tmp/bk_set_live.json");
    println!("wrote /tmp/bk_set_live.json");

    // ---- Persist for downstream tests.
    let a_hex = hex::encode(&a.raw_bytes);
    std::fs::write("/tmp/live_attestation.hex", &a_hex)
        .expect("write /tmp/live_attestation.hex");
    let b_hex = hex::encode(&b_bytes);
    std::fs::write("/tmp/typed_attestation.hex", &b_hex)
        .expect("write /tmp/typed_attestation.hex");
    std::fs::write("/tmp/live_block.boc", &boc).expect("write /tmp/live_block.boc");
    println!(
        "wrote /tmp/live_attestation.hex ({}B hex), /tmp/typed_attestation.hex ({}B hex), /tmp/live_block.boc ({}B)",
        a_hex.len(),
        b_hex.len(),
        boc.len(),
    );
}
