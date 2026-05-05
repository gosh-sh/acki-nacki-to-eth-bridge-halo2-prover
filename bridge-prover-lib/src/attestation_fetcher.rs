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
    // Query both first (genesis-era) and last (recent) bkSetUpdates to capture
    // the full history of adds/removes. Use the light query (no attestation subfields)
    // to avoid database timeouts on large networks.
    let mut updates = client.query_bk_set_updates_light(500, true).await?;
    // Also get the most recent updates.
    let recent = client.query_bk_set_updates_light(500, false).await?;
    // Merge, deduplicating by block_id.
    let existing_ids: std::collections::HashSet<String> =
        updates.iter().map(|u| u.block_id.clone()).collect();
    for u in recent {
        if !existing_ids.contains(&u.block_id) {
            updates.push(u);
        }
    }
    if updates.is_empty() {
        bail!("no bkSetUpdates found — node may not have produced blocks yet");
    }

    // The bk_set_update field is a hex-encoded blob. We need to understand its format
    // by inspecting it. For now, log the raw hex and try to parse.
    let mut bk_set: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut total_adds = 0usize;
    let mut total_removes = 0usize;

    for update in &updates {
        if update.bk_set_update_hex.is_empty() {
            continue;
        }
        let blob = hex::decode(&update.bk_set_update_hex)
            .context("failed to decode bk_set_update hex")?;

        let changes = parse_bk_set_changes(&blob);
        for (variant, signer_idx, pk) in &changes {
            match *variant {
                BK_CHANGE_ADDED => {
                    info!(
                        "  height={:?}: Added signer {} pk={}...",
                        update.height,
                        signer_idx,
                        hex::encode(&pk[..8])
                    );
                    bk_set.insert(*signer_idx, pk.clone());
                    total_adds += 1;
                }
                BK_CHANGE_REMOVED => {
                    info!(
                        "  height={:?}: Removed signer {}",
                        update.height,
                        signer_idx,
                    );
                    bk_set.remove(signer_idx);
                    total_removes += 1;
                }
                _ => {
                    // FutureAdded, ChangedVersion — ignore for BK set reconstruction.
                }
            }
        }
    }

    info!(
        "processed {} bkSetUpdates: {} adds, {} removes, {} active signers",
        updates.len(),
        total_adds,
        total_removes,
        bk_set.len()
    );

    if bk_set.is_empty() {
        bail!(
            "BK set is empty after processing {} bkSetUpdates ({} adds, {} removes). \
             The initial BK set may have been established at genesis and not captured \
             in bkSetUpdates. Use a bk_set.json config file as fallback.",
            updates.len(),
            total_adds,
            total_removes,
        );
    }

    info!("extracted BK set with {} signers: {:?}",
        bk_set.len(), bk_set.keys().collect::<Vec<_>>());
    Ok(bk_set)
}

/// Variant discriminants for BlockKeeperSetChange enum (bincode u32).
const BK_CHANGE_ADDED: u32 = 0;
const BK_CHANGE_REMOVED: u32 = 1;

/// Parse a bk_set_update blob by scanning for pubkey markers.
///
/// The blob is bincode-serialized `Vec<BlockKeeperSetChange>`. Each change contains
/// a variant (u32), signer_index (u16), and BlockKeeperData with a 96-byte pubkey.
/// Rather than parsing the full BlockKeeperData struct (which varies by version),
/// we scan for the `u64(96)` pubkey length marker preceded by variant + signer_index.
///
/// Returns (variant, signer_index, pubkey_bytes) tuples.
fn parse_bk_set_changes(blob: &[u8]) -> Vec<(u32, u16, Vec<u8>)> {
    let mut results = Vec::new();
    if blob.len() < 16 {
        return results;
    }

    let mut i = 8; // skip num_changes u64 header
    while i + 14 + 96 <= blob.len() {
        let variant = u32::from_le_bytes(blob[i..i + 4].try_into().unwrap());
        let signer_idx = u16::from_le_bytes(blob[i + 4..i + 6].try_into().unwrap());
        let pk_len = u64::from_le_bytes(blob[i + 6..i + 14].try_into().unwrap());

        if variant <= 3 && pk_len == 96 && (signer_idx as u32) < 100_000 {
            let pk = blob[i + 14..i + 14 + 96].to_vec();
            results.push((variant, signer_idx, pk));
            i += 14 + 96; // skip past this entry's header + pubkey
            // Skip remaining BlockKeeperData fields (variable length).
            // Advance byte-by-byte until we find the next valid pattern or end.
            continue;
        }
        i += 1;
    }
    results
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
/// The attestation for block N is in the common section of block N+1 (or sometimes N+2).
/// Uses the `blockByHeight` GraphQL query for direct access by seq_no.
pub async fn fetch_attestation_for_block(
    client: &GqlClient,
    target_seq_no: u32,
) -> anyhow::Result<crate::boc_parser::ParsedAttestation> {
    // Try blocks N+1, N+2, N+3 (attestation is usually in N+1).
    for delta in 1..=3u32 {
        let source_seq = target_seq_no as u64 + delta as u64;
        let (source_hash, boc) = match client.query_block_boc_by_seq_no(source_seq).await {
            Ok(r) => r,
            Err(e) => {
                info!("block seq={} not available: {}", source_seq, e);
                continue;
            }
        };

        info!(
            "fetching BOC of block seq={} (hash={}...) to find attestation for seq={}",
            source_seq, &source_hash[..12.min(source_hash.len())], target_seq_no
        );

        let attestations = crate::boc_parser::extract_attestations_from_boc(&boc)?;
        info!(
            "found {} attestations in block seq={}",
            attestations.len(),
            source_seq
        );

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
    }

    bail!(
        "attestation for block seq_no={} not found in blocks {}..{}",
        target_seq_no,
        target_seq_no + 1,
        target_seq_no + 3,
    )
}
