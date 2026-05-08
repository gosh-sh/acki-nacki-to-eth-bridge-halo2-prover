use std::path::Path;
use std::time::{Duration, Instant};

use tracing::{error, info};

use bridge_prover_lib::ipc;
use bridge_prover_lib::keys::KeyManager;
use bridge_prover_lib::poseidon;
use bridge_prover_lib::verifier;
use bridge_prover_lib::Fr;

const PARAMS_DIR: &str = "./params";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_IDLE_WAIT: Duration = Duration::from_secs(600); // 10 min max idle before exit

#[derive(Default)]
struct Stats {
    total_proofs: u32,
    verified_ok: u32,
    verified_failed: u32,
    failures: Vec<(u32, String)>, // (seq_no, error)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    ipc::ensure_proofs_dir();

    info!("=== Bridge Verifier Daemon ===");

    // 1. Load BK set commitment.
    let bk_set_commitment = load_bk_set_commitment().await?;
    info!("BK set commitment: {:?}", bk_set_commitment);

    // 2. Load key manager (SRS + VK only, no PK needed).
    info!("loading SRS and VK...");
    let key_manager = KeyManager::new(Path::new(PARAMS_DIR));
    if key_manager.primary_vk.is_none() {
        anyhow::bail!(
            "primary VK not found in {}. Run the prover first to generate keys.",
            PARAMS_DIR
        );
    }
    info!("VK loaded");

    // 3. Watch for proof files and verify.
    let mut last_seen_seqno: u32 = 0;
    let mut bootstrapped = false;
    let mut stats = Stats::default();
    let mut last_activity = Instant::now();
    let t_total = Instant::now();

    info!("watching proofs/ directory for incoming proofs...");

    loop {
        // If not yet bootstrapped, scan for any proof file to find the starting seq_no.
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

        let next_seqno = last_seen_seqno + 1;
        let proof_path = ipc::proof_file_path(next_seqno);

        if Path::new(&proof_path).exists() {
            last_activity = Instant::now();
            info!("found proof for block {}", next_seqno);

            let request = match ipc::read_proof_request(next_seqno) {
                Ok(r) => r,
                Err(e) => {
                    error!("block {}: failed to read proof file: {}", next_seqno, e);
                    write_failure(next_seqno, &format!("read error: {}", e));
                    stats.total_proofs += 1;
                    stats.verified_failed += 1;
                    stats.failures.push((next_seqno, e.to_string()));
                    last_seen_seqno = next_seqno;
                    continue;
                }
            };

            // Validate request consistency.
            if request.block_seq_no != next_seqno {
                let msg = format!(
                    "seq_no mismatch: file says {} but expected {}",
                    request.block_seq_no, next_seqno
                );
                error!("block {}: {}", next_seqno, msg);
                write_failure(next_seqno, &msg);
                stats.total_proofs += 1;
                stats.verified_failed += 1;
                stats.failures.push((next_seqno, msg));
                last_seen_seqno = next_seqno;
                continue;
            }

            if request.last_seen_block_seqno != last_seen_seqno {
                let msg = format!(
                    "last_seen mismatch: prover says {} but verifier tracked {}",
                    request.last_seen_block_seqno, last_seen_seqno
                );
                error!("block {}: {}", next_seqno, msg);
                write_failure(next_seqno, &msg);
                stats.total_proofs += 1;
                stats.verified_failed += 1;
                stats.failures.push((next_seqno, msg));
                last_seen_seqno = next_seqno;
                continue;
            }

            // Reconstruct public instances.
            let block_id_fr = match ipc::fr_from_hex(&request.block_id_hex) {
                Ok(fr) => fr,
                Err(e) => {
                    let msg = format!("invalid block_id_hex: {}", e);
                    error!("block {}: {}", next_seqno, msg);
                    write_failure(next_seqno, &msg);
                    stats.total_proofs += 1;
                    stats.verified_failed += 1;
                    stats.failures.push((next_seqno, msg));
                    last_seen_seqno = next_seqno;
                    continue;
                }
            };
            let block_seq_no_fr = Fr::from(request.block_seq_no as u64);
            let last_seen_fr = Fr::from(request.last_seen_block_seqno as u64);

            let instances = vec![
                block_id_fr,
                bk_set_commitment,
                block_seq_no_fr,
                last_seen_fr,
            ];

            // Decode proof bytes.
            let proof_bytes = match hex::decode(&request.proof_hex) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("invalid proof_hex: {}", e);
                    error!("block {}: {}", next_seqno, msg);
                    write_failure(next_seqno, &msg);
                    stats.total_proofs += 1;
                    stats.verified_failed += 1;
                    stats.failures.push((next_seqno, msg));
                    last_seen_seqno = next_seqno;
                    continue;
                }
            };

            // Verify proof.
            let t = Instant::now();
            let verified = verifier::verify_primary_proof(&key_manager, &proof_bytes, &instances);
            let verify_time = t.elapsed();

            stats.total_proofs += 1;
            if verified {
                stats.verified_ok += 1;
                info!(
                    "block {}: VERIFIED OK ({:?})",
                    next_seqno, verify_time
                );
                let result = ipc::VerifyResult {
                    block_seq_no: next_seqno,
                    verified: true,
                    error: None,
                };
                ipc::write_result(&result)?;
            } else {
                stats.verified_failed += 1;
                let msg = "proof verification failed".to_string();
                error!(
                    "block {}: VERIFICATION FAILED ({:?})",
                    next_seqno, verify_time
                );
                error!(
                    "  instances: block_id={}, bk_commit={:?}, seq_no={}, last_seen={}",
                    request.block_id_hex, bk_set_commitment, request.block_seq_no,
                    request.last_seen_block_seqno
                );
                stats.failures.push((next_seqno, msg.clone()));
                write_failure(next_seqno, &msg);
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
    info!("total time:            {:?}", elapsed);
    info!("total proofs received: {}", stats.total_proofs);
    info!("verified OK:           {}", stats.verified_ok);
    info!("verified FAILED:       {}", stats.verified_failed);
    if !stats.failures.is_empty() {
        info!("failures:");
        for (seq_no, err) in &stats.failures {
            info!("  block {}: {}", seq_no, err);
        }
    }

    Ok(())
}

const GQL_ENDPOINT: &str = "https://shellnet.ackinacki.org/graphql";
const BK_SET_CONFIG: &str = "./bk_set.json";

async fn load_bk_set_commitment() -> anyhow::Result<Fr> {
    // Try GraphQL first, then config file.
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

/// Scan the proofs/ directory for the first proof file and return its seq_no.
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
        verified: false,
        error: Some(error.to_string()),
    };
    if let Err(e) = ipc::write_result(&result) {
        error!("failed to write result for block {}: {}", seq_no, e);
    }
}
