//! Bridge Prover Daemon — processes key blocks with Circuit 1a + Circuit 2.
//!
//! Flow:
//! 1. Connect to local Docker node via GraphQL
//! 2. Fetch BK set, initialize keys for both circuits
//! 3. Wait for first key block (initialization)
//! 4. For each subsequent key block:
//!    a. Fetch attestation → generate Circuit 1a proof
//!    b. Build layer hashes preimage + chain proofs → generate Circuit 2 proof
//!    c. Send combined proof to verifier via IPC
//!    d. Update state

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tracing::{error, info, warn};

use bridge_prover_lib::Fr;
use bridge_prover_lib::THINNING_FACTOR_P;
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;

use bridge_prover_lib::attestation_fetcher;
use bridge_prover_lib::bootstrap::{self, BootstrapSeed};
use bridge_prover_lib::bridge_state::BridgeState;
use bridge_prover_lib::gql_client::{self, GqlClient};
use bridge_prover_lib::ipc;
use bridge_prover_lib::keys::KeyManager;
use bridge_prover_lib::layer_prover;
use bridge_prover_lib::poseidon;
use bridge_prover_lib::prover;

const GQL_ENDPOINT: &str = "http://localhost/graphql";

// History window size — imported from the node-block-client crate so it can
// never drift from the node. To change the window size, edit
// `node/libs/node-block-client/src/history_proof.rs` in acki-nacki and bump
// the git rev of node-block-client here.
const HISTORY_WINDOW_SIZE: u64 =
    node_block_client::history_proof::HISTORY_PROOF_WINDOW_SIZE as u64;

/// How often to log a heartbeat summary while the loop is running.
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_secs(3);
const SLEEP_ON_RETRY: Duration = Duration::from_secs(5);
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(300);
const PARAMS_DIR: &str = "./params";
const LOGS_DIR: &str = "./logs";
const STATE_FILE: &str = "./state/prover_state.json";
const BK_SET_CONFIG: &str = "./bk_set.json";

#[derive(Default)]
struct Stats {
    key_blocks_processed: u32,
    primary_proofs_ok: u32,
    layer_proofs_ok: u32,
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
    std::fs::create_dir_all("state").ok();
    ipc::ensure_proofs_dir();

    info!("=== Bridge Prover Daemon (Circuit 1a + Circuit 2) ===");
    info!("GQL endpoint: {}", GQL_ENDPOINT);
    info!("history window size: W = {}", HISTORY_WINDOW_SIZE);
    info!("thinning factor:     P = {} (prove every {}-th key block, bundle = {} blocks)",
          THINNING_FACTOR_P, THINNING_FACTOR_P, HISTORY_WINDOW_SIZE * THINNING_FACTOR_P);
    info!("running indefinitely; send SIGINT (Ctrl-C) to shut down cleanly");

    // Graceful-shutdown flag flipped by the Ctrl-C handler. Checked at the top
    // of each loop iteration so we never tear down mid-proof.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = shutdown.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Ctrl-C received, shutting down at next safe point...");
                s.store(true, Ordering::SeqCst);
            }
        });
    }

    // 1. Connect to node.
    let gql = gql_client::create_client(GQL_ENDPOINT)?;
    info!("GraphQL client created");

    // 2. Fetch BK set.
    let bk_set = load_bk_set(&gql).await?;
    let (bk_set_commitment, _) = poseidon::compute_bk_set_poseidon(&bk_set);
    info!("BK set: {} signers, commitment={:?}", bk_set.len(), bk_set_commitment);

    // 3. Initialize key manager (both circuits).
    info!("loading keys...");
    let mut key_manager = KeyManager::new(Path::new(PARAMS_DIR));
    key_manager.ensure_primary_keys(&bk_set)?;
    info!("primary keys ready");
    key_manager.ensure_layer_keys()?;
    info!("layer keys ready");

    // 4. Load or create state.
    let mut state = BridgeState::load(STATE_FILE, HISTORY_WINDOW_SIZE as usize)?;
    info!("state loaded: initialized={}, last_key_block={}", state.initialized, state.stored_last_seen_block_seq_no);

    // 5. If not initialized, derive bootstrap seed from the first key block
    //    and persist it for the verifier.
    //
    //    The prover plays the role of the "deployer" in the production analog:
    //    it queries the node for the first key block envelope, applies the seed
    //    to its own state, AND writes `state/bootstrap_seed.json` so the
    //    verifier (which has no node connection) can mirror the same L1 entry.
    //    See `bridge_prover_lib::bootstrap` for the full rationale.
    if !state.initialized {
        info!("waiting for first key block (height >= {})...", HISTORY_WINDOW_SIZE);
        let bk_hash_bytes: [u8; 32] = bk_set_commitment.to_repr();
        let seed: BootstrapSeed = loop {
            let blocks = gql.query_latest_blocks(5).await?;
            let latest_seq = blocks.iter().map(|(_, s)| *s).max().unwrap_or(0);
            if latest_seq >= HISTORY_WINDOW_SIZE {
                let first_key_seqno = HISTORY_WINDOW_SIZE;
                info!("first key block available at seq_no {}", first_key_seqno);
                match bootstrap::fetch_from_node(&gql, first_key_seqno, bk_hash_bytes).await {
                    Ok(s) => {
                        info!(
                            "first key block: {} history_proofs layers, block_height={}",
                            s.layer_hashes.len(),
                            s.block_height,
                        );
                        break s;
                    }
                    Err(e) => {
                        warn!("could not fetch first key block envelope ({}), retrying...", e);
                        tokio::time::sleep(POLL_INTERVAL).await;
                        continue;
                    }
                }
            }
            info!("latest block: {}, waiting for height {}...", latest_seq, HISTORY_WINDOW_SIZE);
            tokio::time::sleep(POLL_INTERVAL).await;
        };

        seed.apply(&mut state);
        state.save(STATE_FILE)?;
        seed.save(bootstrap::DEFAULT_SEED_PATH)?;
        info!(
            "initialized from seed: seqno={}, height={}, layers={}; seed written to {}",
            seed.block_seq_no,
            seed.block_height,
            seed.layer_hashes.len(),
            bootstrap::DEFAULT_SEED_PATH,
        );
    }

    // 6. Main processing loop — runs until Ctrl-C.
    let mut stats = Stats::default();
    let t_total = Instant::now();
    let mut last_stats_log = Instant::now();

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("shutdown flag set, exiting main loop");
            break;
        }
        if last_stats_log.elapsed() >= STATS_LOG_INTERVAL {
            info!(
                "[heartbeat] processed={}, primary_ok={}, layer_ok={}, verify_ok={}, fail={}, uptime={:?}",
                stats.key_blocks_processed,
                stats.primary_proofs_ok,
                stats.layer_proofs_ok,
                stats.verification_ok,
                stats.verification_failed,
                t_total.elapsed()
            );
            last_stats_log = Instant::now();
        }

        // Poll for new blocks.
        let blocks = gql.query_latest_blocks(5).await?;
        let latest_seq = blocks.iter().map(|(_, s)| *s).max().unwrap_or(0);

        // Find next thinned key block to process (advances by W * P, not W —
        // see bridge_prover_lib::THINNING_FACTOR_P).
        let next_key_seqno = find_next_thinned_key_block(
            state.stored_last_seen_block_seq_no,
            latest_seq,
            HISTORY_WINDOW_SIZE,
            THINNING_FACTOR_P,
        );

        if next_key_seqno.is_none() {
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }
        let target_seqno = next_key_seqno.unwrap();
        info!("=== Processing key block at height {} ===", target_seqno);

        // Fetch attestation for key block (Circuit 1a input).
        let attestation = match attestation_fetcher::fetch_attestation_for_block(
            &gql, target_seqno as u32,
        ).await {
            Ok(att) => att,
            Err(e) => {
                warn!("key block {}: attestation not available ({}), retrying...", target_seqno, e);
                tokio::time::sleep(SLEEP_ON_RETRY).await;
                continue;
            }
        };

        if attestation.target_type != 0 {
            info!("key block {}: fallback attestation, skipping", target_seqno);
            // Move past this key block (cursor advance only, no layer append).
            state.stored_last_seen_block_seq_no = target_seqno;
            state.stored_last_seen_block_height = target_seqno;
            state.save(STATE_FILE)?;
            continue;
        }

        // Verify signers are in BK set.
        let missing: Vec<u16> = attestation.signature_occurrences.keys()
            .filter(|idx| !bk_set.contains_key(idx))
            .cloned()
            .collect();
        if !missing.is_empty() {
            warn!("key block {}: signers {:?} not in BK set, skipping", target_seqno, missing);
            state.stored_last_seen_block_seq_no = target_seqno;
            state.stored_last_seen_block_height = target_seqno;
            state.save(STATE_FILE)?;
            continue;
        }

        let t_proof = Instant::now();

        // ---- Circuit 1a: Primary Attestation Proof ----
        // Load PK on demand, unload after to free ~3.7 GB before Circuit 2.
        info!("key block {}: loading primary PK...", target_seqno);
        key_manager.load_primary_pk()?;

        info!("key block {}: generating Circuit 1a proof...", target_seqno);
        let primary_proof = match prover::generate_primary_proof(
            &key_manager,
            &attestation.raw_bytes,
            &bk_set,
            state.stored_last_seen_block_seq_no as u32,
        ) {
            Ok(output) => {
                stats.primary_proofs_ok += 1;
                key_manager.unload_primary_pk();
                output
            }
            Err(e) => {
                error!("key block {}: Circuit 1a proof failed: {}", target_seqno, e);
                key_manager.unload_primary_pk();
                stats.verification_failed += 1;
                stats.key_blocks_processed += 1;
                state.stored_last_seen_block_seq_no = target_seqno;
                state.stored_last_seen_block_height = target_seqno;
                state.save(STATE_FILE)?;
                continue;
            }
        };
        info!("key block {}: Circuit 1a proof generated", target_seqno);

        // ---- Circuit 2: Layer Hashes Movement Proof ----
        // Inputs are reconstructed from real block data:
        //   - preimage: history_proofs parsed from the target block's CommonSection
        //   - siblings: 8-leaf SHA-256 Merkle path for L0 (Poseidon over the preimage)
        //   - chain_links: real Poseidon Merkle proofs walked across intermediate
        //     key blocks fetched via GraphQL (see real_chain_builder).
        // Load layer PK on demand, unload after to free ~2.8 GB.
        info!("key block {}: loading layer PK...", target_seqno);
        key_manager.load_layer_pk()?;

        info!("key block {}: generating Circuit 2 proof...", target_seqno);
        let layer_proof = match generate_layer_proof_for_key_block(
            &key_manager,
            &gql,
            &state,
            target_seqno,
            &bk_set_commitment,
        ).await {
            Ok(output) => {
                stats.layer_proofs_ok += 1;
                key_manager.unload_layer_pk();
                output
            }
            Err(e) => {
                error!("key block {}: Circuit 2 proof failed: {}", target_seqno, e);
                key_manager.unload_layer_pk();
                stats.verification_failed += 1;
                stats.key_blocks_processed += 1;
                state.stored_last_seen_block_seq_no = target_seqno;
                state.stored_last_seen_block_height = target_seqno;
                state.save(STATE_FILE)?;
                continue;
            }
        };
        info!("key block {}: Circuit 2 proof generated", target_seqno);

        let proof_time = t_proof.elapsed();
        stats.total_proof_time += proof_time;
        info!("key block {}: both proofs generated in {:?}", target_seqno, proof_time);

        // Fetch the envelope once now to extract (a) the authoritative
        // thread-anchored block_height for the ProofRequest, and (b) the
        // layer-hash bundle reused below by `append_bundle`. The envelope is
        // immutable once committed so doing this before vs. after the verifier
        // call is equivalent.
        let (state_layer_hashes, observed_height): (Vec<([u8; 32], u8)>, u64) = match gql
            .query_block_envelope(target_seqno)
            .await
        {
            Ok(envelope) => {
                use node_block_client::BLSSignedEnvelope;
                let cs = envelope.data().common_section();
                let hp = cs.history_proofs();
                let height = *cs.block_height().height();
                let hashes = hp.iter()
                    .map(|(&layer, proof)| (*proof.root_hash(), layer))
                    .collect();
                (hashes, height)
            }
            Err(e) => {
                warn!(
                    "key block {}: envelope fetch failed ({}), using seq_no as height fallback",
                    target_seqno, e
                );
                (Vec::new(), target_seqno)
            }
        };

        // Write combined proof for verifier.
        let request = ipc::ProofRequest {
            schema_version: ipc::PROOF_REQUEST_SCHEMA_VERSION,
            block_seq_no: target_seqno as u32,
            block_height: observed_height,
            last_seen_block_seqno: state.stored_last_seen_block_seq_no as u32,
            block_id_hex: ipc::fr_to_hex(&primary_proof.block_id_fr),
            primary_proof_hex: hex::encode(&primary_proof.proof_bytes),
            layer_proof_hex: hex::encode(&layer_proof.proof_bytes),
            layer_block_id_hex: ipc::fr_to_hex(&layer_proof.block_id_fr),
            bk_set_poseidon_hash_hex: ipc::fr_to_hex(&layer_proof.bk_set_poseidon_hash_fr),
            num_layers: layer_proof.num_layers,
            layer_hash_frs_hex: layer_proof.layer_hash_frs.iter().map(|fr| ipc::fr_to_hex(fr)).collect(),
            prev_max_level_layer_hash_hex: ipc::fr_to_hex(&layer_proof.prev_max_level_layer_hash_fr),
        };
        ipc::write_combined_proof(&request)?;
        info!("key block {}: proof written, waiting for verifier...", target_seqno);

        // Wait for verifier result.
        match ipc::wait_for_result(target_seqno as u32, VERIFIER_TIMEOUT).await {
            Ok(result) => {
                if result.primary_verified && result.layer_verified {
                    info!("key block {}: BOTH VERIFIED OK", target_seqno);
                    stats.verification_ok += 1;
                } else {
                    error!(
                        "key block {}: VERIFICATION FAILED: primary={}, layer={}, err={:?}",
                        target_seqno, result.primary_verified, result.layer_verified, result.error
                    );
                    stats.verification_failed += 1;
                }
            }
            Err(e) => {
                error!("key block {}: verifier timeout/error: {}", target_seqno, e);
                stats.verification_failed += 1;
            }
        }

        // ALWAYS update state with the REAL layer hashes + block_height
        // captured pre-verifier above, regardless of verification result. This
        // ensures subsequent chain proofs use the correct prev_hash even after
        // timeouts or failures, and that the heights[] slot reflects what the
        // node committed (not just our seq_no proxy).
        let bk_hash_bytes: [u8; 32] = bk_set_commitment.to_repr();
        state.append_bundle(
            &state_layer_hashes,
            observed_height,
            target_seqno,
            bk_hash_bytes,
        );

        stats.key_blocks_processed += 1;
        state.save(STATE_FILE)?;
    }

    // Print summary.
    let elapsed = t_total.elapsed();
    info!("\n=== PROVER SUMMARY ===");
    info!("total time:              {:?}", elapsed);
    info!("key blocks processed:    {}", stats.key_blocks_processed);
    info!("primary proofs OK:       {}", stats.primary_proofs_ok);
    info!("layer proofs OK:         {}", stats.layer_proofs_ok);
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

/// Find the next *thinned* key block to process after `last_key_seqno`.
///
/// The daemon advances in steps of `W * P` blocks: it proves only every
/// `P`-th master key block, with each Circuit 2 bundle internally chaining
/// `P` consecutive layer-1 windows via `verify_chain_of_dense_proofs`.
/// The bootstrap step is at `seq = W` (a single W-aligned root applied by
/// the bootstrap seed); from there the first thinned target is `W*P`, then
/// `2*W*P`, etc.
fn find_next_thinned_key_block(
    last_key_seqno: u64,
    latest_seqno: u64,
    window_size: u64,
    thinning_factor: u64,
) -> Option<u64> {
    let step = window_size * thinning_factor;
    // Next multiple of `step` strictly greater than `last_key_seqno`.
    // Works for both bootstrap (`last == window_size`) and steady state
    // (`last == k * step`).
    let next = ((last_key_seqno / step) + 1) * step;
    if next <= latest_seqno {
        Some(next)
    } else {
        None
    }
}

/// Generate Circuit 2 proof for a key block using real block data and real chain proofs.
///
/// Fetches the full AckiNackiBlock `data` field, parses it to extract:
/// - Layer hashes (from history_proofs in CommonSection)
/// - BK set Poseidon hash (from block_keeper_set_change_proof_data)
/// - Merkle tree siblings for L0 in the 8-leaf block_id tree
///
/// Chain proofs are built from real intermediate block data by reconstructing
/// the Poseidon Merkle trees that the node produced.
async fn generate_layer_proof_for_key_block(
    key_manager: &KeyManager,
    gql: &GqlClient,
    state: &BridgeState,
    target_seqno: u64,
    bk_set_commitment: &Fr,
) -> anyhow::Result<layer_prover::LayerProofOutput> {
    use bridge_prover_lib::block_id_tree;
    use bridge_prover_lib::real_chain_builder;
    use node_block_client::BLSSignedEnvelope;

    // 1. Fetch block as Envelope<AckiNackiBlock> via boc deserialization.
    info!("fetching block envelope for seq={}...", target_seqno);
    let envelope = gql
        .query_block_envelope(target_seqno)
        .await
        .context("failed to fetch block envelope")?;

    let common_section = envelope.data().common_section();
    let history_proofs = common_section.history_proofs();

    info!(
        "parsed: history_proofs={} layers",
        history_proofs.len(),
    );

    if history_proofs.is_empty() {
        anyhow::bail!("block {} has no history_proofs", target_seqno);
    }

    // 2. Build layer_hashes_preimage from history_proofs.
    let num_layers = history_proofs.len() as u8;
    let mut root_hashes = Vec::with_capacity(10);
    for i in 1..=10u8 {
        if let Some(proof) = history_proofs.get(&i) {
            root_hashes.push(*proof.root_hash());
        } else {
            root_hashes.push([0u8; 32]);
        }
    }
    let preimage = block_id_tree::build_layer_hashes_preimage(num_layers as usize, &root_hashes);

    // 3. Build the 8-leaf SHA-256 Merkle tree for block_id and siblings.
    // Use the node's own merkle_block_id computation via identifier().
    let block_id_from_envelope = envelope.data().identifier();
    info!(
        "block_id from envelope: {}",
        hex::encode(block_id_from_envelope.as_array())
    );

    // For the Merkle siblings, we still need to compute the tree ourselves.
    // BK set hashes from block_keeper_set_change_proof_data.
    let (bk_old, bk_new) = if let Some(proof_data) =
        common_section.block_keeper_set_change_proof_data()
    {
        let th = proof_data.transition_hashes();
        (*th.old_bk_set_hash(), *th.new_bk_set_hash())
    } else {
        ([0u8; 32], [0u8; 32])
    };

    // L4: TVM block repr_hash (from the AckiNackiBlock's tvm_block_hash helper).
    let tvm_repr_hash = *envelope.data().tvm_block_hash().as_array();

    // L1: SHA-256(common_section.full_hash_data())
    let cs_hash_data = common_section.full_hash_data();

    // L5: SHA-256(bincode(durable_state_update))
    let durable_bytes = bincode::serialize(envelope.data().durable_state_update())
        .expect("Must serialize durable state");

    let tx_cnt = *envelope.data().tx_cnt() as u64;

    let tree = block_id_tree::compute_block_id_tree(
        &preimage,
        &cs_hash_data,
        &bk_old,
        &bk_new,
        &tvm_repr_hash,
        &durable_bytes,
        tx_cnt,
    );
    let siblings = tree.siblings_for_l0();

    // 4. BK set Poseidon hash.
    let bk_set_hash_fr = {
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&bk_old);
        halo2_base::halo2_proofs::halo2curves::bn256::Fr::from_repr(repr)
            .unwrap_or(*bk_set_commitment)
    };

    // 5. Build history_proofs as BTreeMap<u8, [u8; 32]> for the chain builder.
    let history_proofs_map: std::collections::BTreeMap<u8, [u8; 32]> = history_proofs
        .iter()
        .map(|(&layer, proof)| (layer, *proof.root_hash()))
        .collect();

    // 6. Build REAL chain proofs from intermediate block data.
    let chain_result = real_chain_builder::build_real_chain(
        gql,
        state,
        &history_proofs_map,
        target_seqno,
        HISTORY_WINDOW_SIZE,
    )
    .await
    .context("failed to build real chain proofs")?;

    info!("using REAL chain proofs ({} steps)", chain_result.num_steps);

    let prev_hash_fr = gosh_dense_balanced_tree::bytes_to_fr(&chain_result.prev_hash);

    // 7. Generate Circuit 2 proof with real preimage, real siblings, real chain.
    layer_prover::generate_layer_proof(
        key_manager,
        &preimage,
        &siblings,
        prev_hash_fr,
        chain_result.num_steps,
        &chain_result.chain_links,
        bk_set_hash_fr,
    )
}

async fn load_bk_set(gql: &GqlClient) -> anyhow::Result<HashMap<u16, Vec<u8>>> {
    match bridge_prover_lib::bk_set_fetcher::fetch_bk_set(gql).await {
        Ok(bk_set) => return Ok(bk_set),
        Err(e) => {
            warn!("failed to fetch BK set from GraphQL: {}", e);
            info!("trying config file fallback: {}", BK_SET_CONFIG);
        }
    }
    bridge_prover_lib::bk_set_fetcher::load_bk_set_from_config(BK_SET_CONFIG)
        .context("failed to load BK set from both GraphQL and config file")
}
