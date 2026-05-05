use std::collections::HashMap;

use anyhow::{bail, Context};
use tracing::info;

use crate::gql_client::GqlClient;

/// Fetch the initial BK set from the node's bkSetUpdates.
///
/// Queries the first few bkSetUpdates entries, which should contain
/// `BlockKeeperAdded` changes from the zerostate. Returns a map of
/// signer_index -> 48-byte compressed BLS pubkey.
///
/// If no bk_set_updates are available yet, returns an error.
pub async fn fetch_initial_bk_set(
    client: &GqlClient,
) -> anyhow::Result<HashMap<u16, Vec<u8>>> {
    let updates = client.query_bk_set_updates(50).await?;
    if updates.is_empty() {
        bail!("no bkSetUpdates found — node may not have produced blocks yet");
    }

    // The bk_set_update field is a hex-encoded blob. We need to understand its format
    // by inspecting it. For now, log the raw hex and try to parse.
    let mut bk_set: HashMap<u16, Vec<u8>> = HashMap::new();

    for update in &updates {
        if update.bk_set_update_hex.is_empty() {
            continue;
        }
        let blob = hex::decode(&update.bk_set_update_hex)
            .context("failed to decode bk_set_update hex")?;
        info!(
            "bkSetUpdate block_id={}, blob_len={}, height={:?}",
            update.block_id,
            blob.len(),
            update.height,
        );
        // TODO: Parse the blob as bincode Vec<BlockKeeperSetChange> to extract
        // BlockKeeperAdded entries with signer_index and pubkey.
        // For now, we'll try a best-effort parse or fall back to config.
        if let Ok(parsed) = try_parse_bk_set_update(&blob) {
            for (idx, pk) in parsed {
                bk_set.insert(idx, pk);
            }
        }
    }

    if bk_set.is_empty() {
        bail!(
            "could not extract BK set from {} bkSetUpdates. \
             The blob format may need investigation. Raw first blob hex: {}",
            updates.len(),
            updates.first().map(|u| &u.bk_set_update_hex as &str).unwrap_or("(none)")
        );
    }

    info!("extracted BK set with {} signers: {:?}",
        bk_set.len(), bk_set.keys().collect::<Vec<_>>());
    Ok(bk_set)
}

/// Try to parse a bk_set_update blob.
///
/// The blob is expected to be bincode-serialized data containing BK set changes.
/// The exact format depends on the acki-nacki version. This function tries
/// common formats and returns extracted (signer_index, compressed_pubkey) pairs.
fn try_parse_bk_set_update(blob: &[u8]) -> anyhow::Result<Vec<(u16, Vec<u8>)>> {
    // The blob format needs investigation against the live node.
    // For now, return an error to trigger the fallback.
    bail!("bk_set_update blob parsing not yet implemented (blob_len={})", blob.len())
}

/// Load BK set from a JSON config file (fallback for local testing).
///
/// Expected format:
/// ```json
/// { "0": "aabb...48-byte-hex...", "1": "ccdd...", ... }
/// ```
pub fn load_bk_set_from_config(path: &str) -> anyhow::Result<HashMap<u16, Vec<u8>>> {
    let data = std::fs::read_to_string(path).context("failed to read BK set config")?;
    let map: HashMap<String, String> = serde_json::from_str(&data)?;
    let mut bk_set = HashMap::new();
    for (k, v) in &map {
        let idx: u16 = k.parse().context("invalid signer index in config")?;
        let pk_bytes = hex::decode(v).context("invalid pubkey hex in config")?;
        if pk_bytes.len() != 48 {
            bail!("pubkey for signer {} has {} bytes, expected 48", idx, pk_bytes.len());
        }
        bk_set.insert(idx, pk_bytes);
    }
    Ok(bk_set)
}

/// Fetch the attestation for block N by parsing block N+1's BOC.
///
/// Strategy:
/// 1. Query recent blocks to find the hash of block at `target_seq_no + 1`
/// 2. Fetch that block's BOC
/// 3. Parse the BOC to extract attestation envelopes from the common section
/// 4. Find the attestation for `target_seq_no`
pub async fn fetch_attestation_for_block(
    client: &GqlClient,
    target_seq_no: u32,
) -> anyhow::Result<crate::boc_parser::ParsedAttestation> {
    // Find the block at target_seq_no + 1 (or later) that should contain the attestation.
    let blocks = client.query_latest_blocks(200).await?;

    // Find the hash of a block with seq_no > target_seq_no (ideally target_seq_no + 1).
    let source_block = blocks
        .iter()
        .filter(|(_, seq)| *seq > target_seq_no as u64)
        .min_by_key(|(_, seq)| *seq);

    let (source_hash, source_seq) = match source_block {
        Some((h, s)) => (h.clone(), *s),
        None => bail!(
            "no block with seq_no > {} found in latest 200 blocks (max_seq={})",
            target_seq_no,
            blocks.iter().map(|(_, s)| s).max().unwrap_or(&0)
        ),
    };

    info!(
        "fetching BOC of block seq={} (hash={}) to find attestation for seq={}",
        source_seq, &source_hash[..12], target_seq_no
    );

    // Fetch the BOC.
    let boc = client.query_block_boc(&source_hash).await?;
    info!("BOC size: {} bytes", boc.len());

    // Parse attestations from the BOC.
    let attestations = crate::boc_parser::extract_attestations_from_boc(&boc)?;
    info!(
        "found {} attestations in block seq={}",
        attestations.len(),
        source_seq
    );

    // Find the attestation for our target block.
    for att in &attestations {
        if att.block_seq_no == target_seq_no {
            info!(
                "attestation for seq={}: type={}, signers={:?}",
                target_seq_no,
                if att.target_type == 0 { "Primary" } else { "Fallback" },
                att.signature_occurrences
            );
            return Ok(att.clone());
        }
    }

    // If not in the nearest block, try a few more.
    for (hash, seq) in &blocks {
        if *seq <= target_seq_no as u64 || *seq == source_seq {
            continue;
        }
        let boc = client.query_block_boc(hash).await?;
        let atts = crate::boc_parser::extract_attestations_from_boc(&boc)?;
        for att in &atts {
            if att.block_seq_no == target_seq_no {
                return Ok(att.clone());
            }
        }
    }

    bail!(
        "attestation for block seq_no={} not found in any scanned block",
        target_seq_no
    )
}
