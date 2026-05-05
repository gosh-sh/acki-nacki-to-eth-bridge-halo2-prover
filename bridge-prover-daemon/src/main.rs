use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use tracing::{error, info, warn};

use bridge_prover_lib::attestation_fetcher;
use bridge_prover_lib::gql_client;
use bridge_prover_lib::ipc;
use bridge_prover_lib::keys::KeyManager;
use bridge_prover_lib::poseidon;
use bridge_prover_lib::prover;

const MAX_BLOCKS_TO_PROCESS: u32 = 10;
const SLEEP_BETWEEN_BLOCKS: Duration = Duration::from_secs(5);
const SLEEP_ON_RETRY: Duration = Duration::from_secs(5);
const INITIAL_WAIT: Duration = Duration::from_secs(5);
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(120);
const GQL_ENDPOINT: &str = "https://shellnet.ackinacki.org/graphql";
const PARAMS_DIR: &str = "./params";
const LOGS_DIR: &str = "./logs";
const BK_SET_CONFIG: &str = "./bk_set.json";

#[derive(Default)]
struct Stats {
    blocks_processed: u32,
    primary_attestations: u32,
    fallback_attestations: u32,
    skipped_blocks: u32,
    verification_ok: u32,
    verification_failed: u32,
    total_proof_time: Duration,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    std::fs::create_dir_all(LOGS_DIR).ok();
    ipc::ensure_proofs_dir();

    info!("=== Bridge Prover Daemon ===");
    info!("GQL endpoint: {}", GQL_ENDPOINT);
    info!("max blocks: {}", MAX_BLOCKS_TO_PROCESS);

    // 1. Connect to node.
    let gql = gql_client::create_client(GQL_ENDPOINT)?;
    info!("GraphQL client created");

    // 2. Fetch BK set.
    let bk_set = load_bk_set(&gql).await?;
    let bk_set_commitment = poseidon::compute_bk_set_poseidon(
        &bk_set,
        bridge_prover_lib::keys::circuit_limb_bits(),
        bridge_prover_lib::keys::circuit_num_limbs(),
    );
    info!(
        "BK set: {} signers, commitment={:?}",
        bk_set.len(),
        bk_set_commitment
    );

    // 3. Initialize key manager (loads SRS, tries cached VK/PK).
    info!("loading keys...");
    let mut key_manager = KeyManager::new(Path::new(PARAMS_DIR));
    key_manager.ensure_primary_keys(&bk_set)?;
    info!("keys ready");

    // 4. Find a recent starting block (we need blocks whose attestations use the current BK set).
    info!("finding starting block...");
    tokio::time::sleep(INITIAL_WAIT).await;
    let blocks = gql.query_latest_blocks(20).await?;
    let latest_seq = blocks.iter().map(|(_, s)| *s).max().unwrap_or(0);
    // Start a few blocks behind the latest so attestations are available.
    let start_seq = if latest_seq > 3 { (latest_seq - 3) as u32 } else { 1 };
    let mut last_seen_seqno: u32 = start_seq.saturating_sub(1);
    info!(
        "latest block on node: seq_no={}, starting from: seq_no={} (last_seen={})",
        latest_seq, start_seq, last_seen_seqno
    );

    // 5. Main loop.
    let mut stats = Stats::default();
    let t_total = Instant::now();

    while stats.blocks_processed < MAX_BLOCKS_TO_PROCESS {
        let target_seqno = last_seen_seqno + 1;

        match attestation_fetcher::fetch_attestation_for_block(&gql, target_seqno).await {
            Ok(att) => {
                if att.target_type == 0 {
                    stats.primary_attestations += 1;
                } else {
                    stats.fallback_attestations += 1;
                }

                if att.target_type != 0 {
                    info!(
                        "block {}: fallback attestation (type={}), skipping for now",
                        target_seqno, att.target_type
                    );
                    stats.skipped_blocks += 1;
                    last_seen_seqno = target_seqno;
                    continue;
                }

                info!("block {}: primary attestation found, {} signers, indices={:?}",
                    target_seqno, att.signature_occurrences.len(),
                    att.signature_occurrences.keys().collect::<Vec<_>>());

                // Verify all attestation signers are in our BK set.
                let missing: Vec<u16> = att.signature_occurrences.keys()
                    .filter(|idx| !bk_set.contains_key(idx))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    warn!(
                        "block {}: attestation has signers {:?} not in current BK set {:?}, skipping \
                         (BK set may have rotated since this block was produced)",
                        target_seqno, missing, bk_set.keys().collect::<Vec<_>>()
                    );
                    stats.skipped_blocks += 1;
                    last_seen_seqno = target_seqno;
                    continue;
                }

                // The raw_bytes from BOC parsing are already in the correct
                // bincode Envelope<AttestationData> format.
                let att_bytes = &att.raw_bytes;

                // Generate proof.
                let t = Instant::now();
                let proof_output = match prover::generate_primary_proof(
                    &key_manager,
                    att_bytes,
                    &bk_set,
                    last_seen_seqno,
                ) {
                    Ok(output) => output,
                    Err(e) => {
                        error!("block {}: proof generation failed: {}", target_seqno, e);
                        log_witnesses(target_seqno, att_bytes, &bk_set, last_seen_seqno);
                        stats.verification_failed += 1;
                        stats.blocks_processed += 1;
                        last_seen_seqno = target_seqno;
                        continue;
                    }
                };
                let proof_time = t.elapsed();
                stats.total_proof_time += proof_time;
                info!("block {}: proof generated in {:?}", target_seqno, proof_time);

                // Write proof for verifier.
                ipc::write_proof(target_seqno, &proof_output)?;
                info!("block {}: proof written, waiting for verifier...", target_seqno);

                // Wait for verifier result.
                match ipc::wait_for_result(target_seqno, VERIFIER_TIMEOUT).await {
                    Ok(result) => {
                        if result.verified {
                            info!("block {}: VERIFIED OK", target_seqno);
                            stats.verification_ok += 1;
                        } else {
                            error!(
                                "block {}: VERIFICATION FAILED: {}",
                                target_seqno,
                                result.error.as_deref().unwrap_or("unknown")
                            );
                            log_witnesses(target_seqno, &att_bytes, &bk_set, last_seen_seqno);
                            stats.verification_failed += 1;
                        }
                    }
                    Err(e) => {
                        error!("block {}: verifier timeout/error: {}", target_seqno, e);
                        stats.verification_failed += 1;
                    }
                }

                stats.blocks_processed += 1;
                last_seen_seqno = target_seqno;
                tokio::time::sleep(SLEEP_BETWEEN_BLOCKS).await;
            }
            Err(e) => {
                warn!(
                    "block {}: attestation not available ({}), retrying...",
                    target_seqno, e
                );
                tokio::time::sleep(SLEEP_ON_RETRY).await;
            }
        }
    }

    // Print summary.
    let elapsed = t_total.elapsed();
    info!("\n=== PROVER SUMMARY ===");
    info!("total time:              {:?}", elapsed);
    info!("blocks processed:        {}", stats.blocks_processed);
    info!("primary attestations:    {}", stats.primary_attestations);
    info!("fallback attestations:   {}", stats.fallback_attestations);
    info!("skipped blocks:          {}", stats.skipped_blocks);
    info!("verification OK:         {}", stats.verification_ok);
    info!("verification FAILED:     {}", stats.verification_failed);
    if stats.verification_ok > 0 {
        info!(
            "avg proof time:          {:?}",
            stats.total_proof_time / stats.verification_ok
        );
    }

    Ok(())
}

async fn load_bk_set(gql: &gql_client::GqlClient) -> anyhow::Result<HashMap<u16, Vec<u8>>> {
    // Try GraphQL first.
    match bridge_prover_lib::bk_set_fetcher::fetch_bk_set(gql).await {
        Ok(bk_set) => return Ok(bk_set),
        Err(e) => {
            warn!("failed to fetch BK set from GraphQL: {}", e);
            info!("trying config file fallback: {}", BK_SET_CONFIG);
        }
    }
    // Fallback to config file.
    bridge_prover_lib::bk_set_fetcher::load_bk_set_from_config(BK_SET_CONFIG)
        .context("failed to load BK set from both GraphQL and config file")
}

fn log_witnesses(
    seq_no: u32,
    att_bytes: &[u8],
    bk_set: &HashMap<u16, Vec<u8>>,
    last_seen: u32,
) {
    let log_path = format!("{}/block_{:06}_witnesses.json", LOGS_DIR, seq_no);
    let bk_set_hex: HashMap<String, String> = bk_set
        .iter()
        .map(|(k, v)| (k.to_string(), hex::encode(v)))
        .collect();
    let log_data = serde_json::json!({
        "block_seq_no": seq_no,
        "attestation_bytes_hex": hex::encode(att_bytes),
        "bk_set": bk_set_hex,
        "last_seen_block_seqno": last_seen,
    });
    if let Err(e) = std::fs::write(&log_path, serde_json::to_string_pretty(&log_data).unwrap()) {
        error!("failed to write witness log to {}: {}", log_path, e);
    } else {
        info!("witnesses logged to {}", log_path);
    }
}
