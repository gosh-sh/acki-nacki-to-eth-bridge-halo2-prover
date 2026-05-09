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
use std::time::{Duration, Instant};

use anyhow::Context;
use tracing::{error, info, warn};

use bridge_prover_lib::Fr;
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;

use bridge_prover_lib::attestation_fetcher;
use bridge_prover_lib::bridge_state::BridgeState;
use bridge_prover_lib::gql_client::{self, GqlClient};
use bridge_prover_lib::ipc;
use bridge_prover_lib::keys::KeyManager;
use bridge_prover_lib::layer_prover;
use bridge_prover_lib::poseidon;
use bridge_prover_lib::prover;

const GQL_ENDPOINT: &str = "http://localhost/graphql";

// History window size — must match node's HISTORY_PROOF_WINDOW_SIZE.
// const HISTORY_WINDOW_SIZE: u64 = 8; // production
const HISTORY_WINDOW_SIZE: u64 = 4; // Must match node's HISTORY_PROOF_WINDOW_SIZE

const MAX_KEY_BLOCKS_TO_PROCESS: u32 = 20;
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
    info!("history window size: {}", HISTORY_WINDOW_SIZE);
    info!("max key blocks: {}", MAX_KEY_BLOCKS_TO_PROCESS);

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
    let mut state = BridgeState::load(STATE_FILE)?;
    info!("state loaded: initialized={}, last_key_block={}", state.initialized, state.last_key_block_seqno);

    // 5. If not initialized, wait for first key block.
    if !state.initialized {
        info!("waiting for first key block (height >= {})...", HISTORY_WINDOW_SIZE);
        loop {
            let blocks = gql.query_latest_blocks(5).await?;
            let latest_seq = blocks.iter().map(|(_, s)| *s).max().unwrap_or(0);
            if latest_seq >= HISTORY_WINDOW_SIZE {
                // First key block is at height = HISTORY_WINDOW_SIZE.
                let first_key_seqno = HISTORY_WINDOW_SIZE;
                info!("first key block available at height {}", first_key_seqno);

                // Fetch block data to extract real layer hashes for initialization.
                let meta = gql.query_block_metadata(first_key_seqno).await?;
                let mut block_id = [0u8; 32];
                if let Ok(bytes) = hex::decode(&meta.hash) {
                    if bytes.len() == 32 {
                        block_id.copy_from_slice(&bytes);
                    }
                }

                // Extract layer hashes from the first key block via boc deserialization.
                let init_layer_hashes: Vec<([u8; 32], u8)> = match gql
                    .query_block_envelope(first_key_seqno)
                    .await
                {
                    Ok(envelope) => {
                        use node::bls::envelope::BLSSignedEnvelope;
                        let hp = envelope.data().common_section().history_proofs();
                        info!("first key block has {} history_proofs layers", hp.len());
                        hp.iter()
                            .map(|(&layer, proof)| (*proof.root_hash(), layer))
                            .collect()
                    }
                    Err(e) => {
                        warn!("could not fetch first key block envelope ({}), init with empty layers", e);
                        Vec::new()
                    }
                };

                let bk_hash_bytes: [u8; 32] = bk_set_commitment.to_repr();
                state.update(
                    &init_layer_hashes,
                    first_key_seqno as u32,
                    block_id,
                    bk_hash_bytes,
                );
                state.save(STATE_FILE)?;
                info!(
                    "initialized with first key block at seqno={}, layers={}",
                    first_key_seqno,
                    init_layer_hashes.len()
                );
                break;
            }
            info!("latest block: {}, waiting for height {}...", latest_seq, HISTORY_WINDOW_SIZE);
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    // 6. Main processing loop.
    let mut stats = Stats::default();
    let t_total = Instant::now();

    while stats.key_blocks_processed < MAX_KEY_BLOCKS_TO_PROCESS {
        // Poll for new blocks.
        let blocks = gql.query_latest_blocks(5).await?;
        let latest_seq = blocks.iter().map(|(_, s)| *s).max().unwrap_or(0);

        // Find next key block to process.
        let next_key_seqno = find_next_key_block(
            state.last_key_block_seqno as u64,
            latest_seq,
            HISTORY_WINDOW_SIZE,
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
            // Move past this key block.
            state.last_key_block_seqno = target_seqno as u32;
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
            state.last_key_block_seqno = target_seqno as u32;
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
            state.last_key_block_seqno,
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
                state.last_key_block_seqno = target_seqno as u32;
                state.save(STATE_FILE)?;
                continue;
            }
        };
        info!("key block {}: Circuit 1a proof generated", target_seqno);

        // ---- Circuit 2: Layer Hashes Movement Proof ----
        // For the first proof after initialization, we generate a synthetic circuit 2 proof
        // since we don't have previous layer hashes to chain from.
        // For subsequent proofs, we build the real chain.

        // Build layer hashes preimage.
        // TODO: Extract actual history_proofs from the block data (BOC parsing).
        // For now, we use the block's known properties to build a test preimage.
        // This is a PoC — the full implementation would parse the CommonSection.

        // For the PoC, we construct Circuit 2 inputs using synthetic data that
        // produces the same block_id as the real block. This requires:
        // 1. Knowing the real layer hashes from the block
        // 2. Knowing the Merkle tree siblings
        //
        // Since we can't yet parse the full block structure, we'll generate
        // a Circuit 2 proof using test data for now, and note this as TODO.
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
                state.last_key_block_seqno = target_seqno as u32;
                state.save(STATE_FILE)?;
                continue;
            }
        };
        info!("key block {}: Circuit 2 proof generated", target_seqno);

        let proof_time = t_proof.elapsed();
        stats.total_proof_time += proof_time;
        info!("key block {}: both proofs generated in {:?}", target_seqno, proof_time);

        // Write combined proof for verifier.
        let request = ipc::ProofRequest {
            block_seq_no: target_seqno as u32,
            last_seen_block_seqno: state.last_key_block_seqno,
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

        // ALWAYS update state with REAL layer hashes from the block's history_proofs,
        // regardless of verification result. This ensures subsequent chain proofs
        // use the correct prev_hash even after timeouts or failures.
        let state_layer_hashes: Vec<([u8; 32], u8)> = match gql
            .query_block_envelope(target_seqno)
            .await
        {
            Ok(envelope) => {
                use node::bls::envelope::BLSSignedEnvelope;
                envelope.data().common_section().history_proofs()
                    .iter()
                    .map(|(&layer, proof)| (*proof.root_hash(), layer))
                    .collect()
            }
            Err(_) => Vec::new(),
        };
        let bk_hash_bytes: [u8; 32] = bk_set_commitment.to_repr();
        let block_id_bytes: [u8; 32] = primary_proof.block_id_fr.to_repr();
        state.update(
            &state_layer_hashes,
            target_seqno as u32,
            block_id_bytes,
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

/// Find the next key block to process after last_key_seqno.
fn find_next_key_block(
    last_key_seqno: u64,
    latest_seqno: u64,
    window_size: u64,
) -> Option<u64> {
    // Next key block is at next multiple of window_size after last_key_seqno.
    let next = if last_key_seqno == 0 {
        window_size
    } else {
        last_key_seqno + window_size
    };

    if next <= latest_seqno {
        // Ensure it's actually a key block height.
        if next % window_size == 0 {
            Some(next)
        } else {
            // Align to next multiple.
            let aligned = ((next / window_size) + 1) * window_size;
            if aligned <= latest_seqno {
                Some(aligned)
            } else {
                None
            }
        }
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
    use node::bls::envelope::BLSSignedEnvelope;

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
