//! Bridge Verifier Daemon — verifies Circuit 1a + Circuit 2 proofs.
//!
//! Watches the proofs/ directory for combined proof files from the prover daemon.
//! Verifies both proofs, cross-references public instances, updates state.

use std::path::Path;
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use bridge_prover_lib::bridge_state::BridgeState;
use bridge_prover_lib::ipc;
use bridge_prover_lib::keys::KeyManager;
use bridge_prover_lib::layer_verifier;
use bridge_prover_lib::poseidon;
use bridge_prover_lib::verifier;
use bridge_prover_lib::Fr;

use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;

const PARAMS_DIR: &str = "./params";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_IDLE_WAIT: Duration = Duration::from_secs(600);
const STATE_FILE: &str = "./state/verifier_state.json";
const GQL_ENDPOINT: &str = "http://localhost/graphql";
const BK_SET_CONFIG: &str = "./bk_set.json";

#[derive(Default)]
struct Stats {
    total_proofs: u32,
    both_verified_ok: u32,
    primary_only_ok: u32,
    layer_only_ok: u32,
    both_failed: u32,
    failures: Vec<(u32, String)>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    std::fs::create_dir_all("state").ok();
    ipc::ensure_proofs_dir();

    info!("=== Bridge Verifier Daemon (Circuit 1a + Circuit 2) ===");

    // 1. Load BK set commitment (for Circuit 1a verification reference).
    let bk_set_commitment = load_bk_set_commitment().await?;
    info!("BK set commitment: {:?}", bk_set_commitment);

    // 2. Load key manager (SRS + VKs only, no PKs needed).
    info!("loading SRS and VKs...");
    let key_manager = KeyManager::new(Path::new(PARAMS_DIR));
    if key_manager.primary_vk.is_none() {
        anyhow::bail!(
            "primary VK not found in {}. Run the prover first to generate keys.",
            PARAMS_DIR
        );
    }
    if key_manager.layer_vk.is_none() {
        anyhow::bail!(
            "layer VK not found in {}. Run the prover first to generate keys.",
            PARAMS_DIR
        );
    }
    info!("VKs loaded (primary + layer)");

    // 3. Load state.
    let mut state = BridgeState::load(STATE_FILE)?;
    info!(
        "state loaded: initialized={}, last_key_block={}",
        state.initialized, state.last_key_block_seqno
    );

    // 4. Watch for proof files and verify.
    let mut last_seen_seqno: u32 = state.last_key_block_seqno;
    let mut bootstrapped = state.initialized;
    let mut stats = Stats::default();
    let mut last_activity = Instant::now();
    let t_total = Instant::now();

    info!("watching proofs/ directory for incoming proofs...");

    loop {
        // If not bootstrapped, scan for first proof file.
        if !bootstrapped {
            if let Some(first_seqno) = scan_for_first_proof() {
                info!("bootstrapping: found first proof at seq_no={}", first_seqno);
                let request = ipc::read_proof_request(first_seqno).ok();
                if let Some(req) = request {
                    last_seen_seqno = req.last_seen_block_seqno;
                    info!("setting initial last_seen={} from first proof", last_seen_seqno);
                }
                bootstrapped = true;
            }
        }

        // Look for proofs with seq_no > last_seen_seqno.
        // Since key blocks may not be consecutive, scan for any proof file.
        let next_proof = find_next_proof_file(last_seen_seqno);

        if let Some(next_seqno) = next_proof {
            last_activity = Instant::now();
            info!("found proof for key block {}", next_seqno);

            let request = match ipc::read_proof_request(next_seqno) {
                Ok(r) => r,
                Err(e) => {
                    error!("block {}: failed to read proof file: {}", next_seqno, e);
                    write_failure(next_seqno, &format!("read error: {}", e));
                    stats.total_proofs += 1;
                    stats.both_failed += 1;
                    stats.failures.push((next_seqno, e.to_string()));
                    last_seen_seqno = next_seqno;
                    continue;
                }
            };

            // Validate consistency.
            if request.last_seen_block_seqno != last_seen_seqno {
                let msg = format!(
                    "last_seen mismatch: prover says {} but verifier tracked {}",
                    request.last_seen_block_seqno, last_seen_seqno
                );
                warn!("block {}: {} (proceeding anyway for PoC)", next_seqno, msg);
            }

            // ---- Verify Circuit 1a ----
            let block_id_fr = match ipc::fr_from_hex(&request.block_id_hex) {
                Ok(fr) => fr,
                Err(e) => {
                    let msg = format!("invalid block_id_hex: {}", e);
                    error!("block {}: {}", next_seqno, msg);
                    write_failure(next_seqno, &msg);
                    stats.total_proofs += 1;
                    stats.both_failed += 1;
                    last_seen_seqno = next_seqno;
                    continue;
                }
            };

            let bk_set_hash_fr = match ipc::fr_from_hex(&request.bk_set_poseidon_hash_hex) {
                Ok(fr) => fr,
                Err(e) => {
                    let msg = format!("invalid bk_set_poseidon_hash_hex: {}", e);
                    error!("block {}: {}", next_seqno, msg);
                    write_failure(next_seqno, &msg);
                    stats.total_proofs += 1;
                    stats.both_failed += 1;
                    last_seen_seqno = next_seqno;
                    continue;
                }
            };

            let primary_proof_bytes = match hex::decode(&request.primary_proof_hex) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("invalid primary_proof_hex: {}", e);
                    error!("block {}: {}", next_seqno, msg);
                    write_failure(next_seqno, &msg);
                    stats.total_proofs += 1;
                    stats.both_failed += 1;
                    last_seen_seqno = next_seqno;
                    continue;
                }
            };

            let block_seq_no_fr = Fr::from(request.block_seq_no as u64);
            let last_seen_fr = Fr::from(request.last_seen_block_seqno as u64);

            let primary_instances = vec![
                block_id_fr,
                bk_set_hash_fr,
                block_seq_no_fr,
                last_seen_fr,
            ];

            let t = Instant::now();
            let primary_verified = verifier::verify_primary_proof(
                &key_manager,
                &primary_proof_bytes,
                &primary_instances,
            );
            let primary_time = t.elapsed();
            info!(
                "block {}: Circuit 1a {} ({:?})",
                next_seqno,
                if primary_verified { "VERIFIED" } else { "FAILED" },
                primary_time
            );

            // ---- Verify Circuit 2 ----
            let layer_proof_bytes = match hex::decode(&request.layer_proof_hex) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("invalid layer_proof_hex: {}", e);
                    error!("block {}: {}", next_seqno, msg);
                    write_failure(next_seqno, &msg);
                    stats.total_proofs += 1;
                    stats.both_failed += 1;
                    last_seen_seqno = next_seqno;
                    continue;
                }
            };

            let prev_hash_fr = match ipc::fr_from_hex(&request.prev_max_level_layer_hash_hex) {
                Ok(fr) => fr,
                Err(e) => {
                    let msg = format!("invalid prev_max_level_layer_hash_hex: {}", e);
                    error!("block {}: {}", next_seqno, msg);
                    write_failure(next_seqno, &msg);
                    stats.total_proofs += 1;
                    stats.both_failed += 1;
                    last_seen_seqno = next_seqno;
                    continue;
                }
            };

            // Build Circuit 2 public instances (14 values).
            let mut layer_instances = Vec::with_capacity(14);
            // Circuit 2 computes its own block_id from the Merkle path.
            let layer_block_id_hex = request.layer_block_id_hex.as_str();
            let layer_block_id_fr = match ipc::fr_from_hex(layer_block_id_hex) {
                Ok(fr) => fr,
                Err(_) => {
                    // Fallback for old proof files without layer_block_id_hex.
                    ipc::fr_from_hex(&request.block_id_hex).unwrap_or(Fr::zero())
                }
            };
            layer_instances.push(layer_block_id_fr);     // [0] block_id
            layer_instances.push(bk_set_hash_fr);        // [1] bk_set_poseidon_hash
            layer_instances.push(Fr::from(request.num_layers as u64)); // [2] num_layers
            for hex_str in &request.layer_hash_frs_hex {
                let fr = ipc::fr_from_hex(hex_str).unwrap_or(Fr::zero());
                layer_instances.push(fr);                // [3..12]
            }
            // Pad to 10 layer hashes if needed.
            while layer_instances.len() < 13 {
                layer_instances.push(Fr::zero());
            }
            layer_instances.push(prev_hash_fr);          // [13]

            let t = Instant::now();
            let layer_verified = layer_verifier::verify_layer_proof(
                &key_manager,
                &layer_proof_bytes,
                &layer_instances,
            );
            let layer_time = t.elapsed();
            info!(
                "block {}: Circuit 2 {} ({:?})",
                next_seqno,
                if layer_verified { "VERIFIED" } else { "FAILED" },
                layer_time
            );

            // Record results.
            stats.total_proofs += 1;
            let result = ipc::VerifyResult {
                block_seq_no: next_seqno,
                primary_verified,
                layer_verified,
                error: if primary_verified && layer_verified {
                    None
                } else {
                    Some(format!(
                        "primary={}, layer={}",
                        primary_verified, layer_verified
                    ))
                },
            };
            ipc::write_result(&result)?;

            if primary_verified && layer_verified {
                stats.both_verified_ok += 1;
                info!("block {}: BOTH VERIFIED OK", next_seqno);

                // Update verifier state.
                let new_layer_hashes: Vec<([u8; 32], u8)> = request.layer_hash_frs_hex
                    .iter()
                    .enumerate()
                    .take(request.num_layers as usize)
                    .map(|(i, hex_str)| {
                        let fr = ipc::fr_from_hex(hex_str).unwrap_or(Fr::zero());
                        let bytes: [u8; 32] = fr.to_repr();
                        (bytes, (i + 1) as u8)
                    })
                    .collect();
                let bk_hash_bytes: [u8; 32] = bk_set_hash_fr.to_repr();
                let block_id_bytes: [u8; 32] = block_id_fr.to_repr();
                state.update(
                    &new_layer_hashes,
                    next_seqno,
                    block_id_bytes,
                    bk_hash_bytes,
                );
                state.save(STATE_FILE)?;
            } else if primary_verified {
                stats.primary_only_ok += 1;
            } else if layer_verified {
                stats.layer_only_ok += 1;
            } else {
                stats.both_failed += 1;
                stats.failures.push((next_seqno, "both circuits failed".to_string()));
            }

            last_seen_seqno = next_seqno;
        } else {
            // No new proof yet.
            if last_activity.elapsed() > MAX_IDLE_WAIT {
                info!("no new proofs for {:?}, shutting down", MAX_IDLE_WAIT);
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    // Print summary.
    let elapsed = t_total.elapsed();
    info!("\n=== VERIFIER SUMMARY ===");
    info!("total time:             {:?}", elapsed);
    info!("total proofs received:  {}", stats.total_proofs);
    info!("both verified OK:       {}", stats.both_verified_ok);
    info!("primary only OK:        {}", stats.primary_only_ok);
    info!("layer only OK:          {}", stats.layer_only_ok);
    info!("both failed:            {}", stats.both_failed);
    if !stats.failures.is_empty() {
        info!("failures:");
        for (seq_no, err) in &stats.failures {
            info!("  block {}: {}", seq_no, err);
        }
    }

    Ok(())
}

async fn load_bk_set_commitment() -> anyhow::Result<Fr> {
    let bk_set = match bridge_prover_lib::gql_client::create_client(GQL_ENDPOINT) {
        Ok(gql) => match bridge_prover_lib::bk_set_fetcher::fetch_bk_set(&gql).await {
            Ok(bk) => {
                info!("BK set loaded from GraphQL: {} signers", bk.len());
                bk
            }
            Err(e) => {
                info!("GraphQL BK set failed ({}), trying config file", e);
                bridge_prover_lib::bk_set_fetcher::load_bk_set_from_config(BK_SET_CONFIG)?
            }
        },
        Err(_) => bridge_prover_lib::bk_set_fetcher::load_bk_set_from_config(BK_SET_CONFIG)?,
    };
    Ok(poseidon::compute_bk_set_poseidon(&bk_set).0)
}

/// Scan proofs/ for any proof file with seq_no > last_seen.
fn find_next_proof_file(last_seen: u32) -> Option<u32> {
    let dir = match std::fs::read_dir("proofs") {
        Ok(d) => d,
        Err(_) => return None,
    };
    let mut candidates: Vec<u32> = dir
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("proof_") && name.ends_with(".json") {
                let num_str = name.trim_start_matches("proof_").trim_end_matches(".json");
                num_str.parse::<u32>().ok()
            } else {
                None
            }
        })
        .filter(|&seq| seq > last_seen)
        .collect();
    candidates.sort();
    candidates.first().copied()
}

/// Scan for the first proof file.
fn scan_for_first_proof() -> Option<u32> {
    let dir = std::fs::read_dir("proofs").ok()?;
    let mut proof_seqnos: Vec<u32> = dir
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("proof_") && name.ends_with(".json") {
                let num_str = name.trim_start_matches("proof_").trim_end_matches(".json");
                num_str.parse::<u32>().ok()
            } else {
                None
            }
        })
        .collect();
    proof_seqnos.sort();
    proof_seqnos.first().copied()
}

fn write_failure(seq_no: u32, error: &str) {
    let result = ipc::VerifyResult {
        block_seq_no: seq_no,
        primary_verified: false,
        layer_verified: false,
        error: Some(error.to_string()),
    };
    if let Err(e) = ipc::write_result(&result) {
        error!("failed to write result for block {}: {}", seq_no, e);
    }
}
