use std::collections::HashMap;

use anyhow::{bail, Context};
use tracing::info;

use crate::gql_client::{GqlAttestation, GqlClient};

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

/// Fetch attestations for blocks near a target seq_no.
///
/// Queries bkSetUpdates and their attestations, looking for a primary attestation
/// whose `block_id` corresponds to a block with the given seq_no.
///
/// Since the GraphQL API doesn't directly support filtering attestations by seq_no,
/// we fetch recent bkSetUpdates and search through their attestations.
pub async fn fetch_attestation_near_seqno(
    client: &GqlClient,
    target_seq_no: u32,
) -> anyhow::Result<GqlAttestation> {
    // Strategy: query recent blocks to find the block hash for our target seq_no,
    // then search attestations for that block_id.
    let blocks = client.query_latest_blocks(200).await?;
    let target_block_hash = blocks
        .iter()
        .find(|(_, seq)| *seq == target_seq_no as u64)
        .map(|(hash, _)| hash.clone());

    let target_hash = match target_block_hash {
        Some(h) => h,
        None => bail!(
            "block with seq_no={} not found in latest 200 blocks (available: {:?})",
            target_seq_no,
            blocks.iter().map(|(_, s)| s).collect::<Vec<_>>()
        ),
    };

    // Now search attestations for this block_id.
    let updates = client.query_bk_set_updates(200).await?;
    for update in &updates {
        for att in &update.attestations {
            if att.block_id == target_hash {
                return Ok(att.clone());
            }
        }
    }

    bail!(
        "no attestation found for block seq_no={} (hash={})",
        target_seq_no,
        target_hash
    )
}
