//! Fetch and reconstruct the Block Keeper (BK) set from a node's GraphQL API.

use std::collections::HashMap;

use anyhow::{bail, Context};
use halo2_base::halo2_proofs::halo2curves::bls12_381::G1Affine;
use tracing::info;

use crate::gql_client::GqlClient;

/// Fetch the current BK set from the node's GraphQL `bkSetUpdates`.
///
/// Queries the full history of BK set changes (adds/removes) and reconstructs
/// the current active validator set. Returns a map of signer_index -> 48-byte
/// compressed BLS pubkey.
pub async fn fetch_bk_set(client: &GqlClient) -> anyhow::Result<HashMap<u16, Vec<u8>>> {
    // Query both first (genesis-era) and last (recent) bkSetUpdates to capture
    // the full history of adds/removes. Use the light query (no attestation subfields)
    // to avoid database timeouts on large networks.
    let mut updates = client.query_bk_set_updates_light(500, true).await?;
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
        for path in ["bk_set.json", "../bk_set.json"] {
            if std::path::Path::new(path).exists() {
                info!(
                    "no bkSetUpdates on node; falling back to BK set config file {}",
                    path
                );
                return load_bk_set_from_config(path);
            }
        }
        bail!(
            "no bkSetUpdates found and no bk_set.json fallback — genesis BK set may not be \
             captured in gql history; place a signer_index→pubkey map in bk_set.json"
        );
    }

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
                _ => {}
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

    let bk_set = normalize_bk_set_pubkeys(bk_set)?;
    info!(
        "extracted BK set with {} signers: {:?}",
        bk_set.len(),
        bk_set.keys().collect::<Vec<_>>()
    );
    Ok(bk_set)
}

/// Load BK set from a JSON config file (fallback).
///
/// Format: `{ "0": "hex-pubkey", "1": "hex-pubkey", ... }`
pub fn load_bk_set_from_config(path: &str) -> anyhow::Result<HashMap<u16, Vec<u8>>> {
    let data = std::fs::read_to_string(path).context("failed to read BK set config")?;
    let map: HashMap<String, String> = serde_json::from_str(&data)?;
    let mut bk_set = HashMap::new();
    for (k, v) in &map {
        let idx: u16 = k.parse().context("invalid signer index in config")?;
        let pk_bytes = hex::decode(v).context("invalid pubkey hex in config")?;
        if pk_bytes.len() != 48 && pk_bytes.len() != 96 {
            bail!(
                "pubkey for signer {} has {} bytes, expected 48 or 96",
                idx,
                pk_bytes.len()
            );
        }
        bk_set.insert(idx, pk_bytes);
    }
    normalize_bk_set_pubkeys(bk_set)
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

/// Normalize pubkeys: compress 96-byte uncompressed keys to 48-byte compressed.
fn normalize_bk_set_pubkeys(
    bk_set: HashMap<u16, Vec<u8>>,
) -> anyhow::Result<HashMap<u16, Vec<u8>>> {
    let mut normalized = HashMap::new();
    for (idx, pk_bytes) in bk_set {
        let compressed = match pk_bytes.len() {
            48 => pk_bytes,
            96 => {
                let bytes: [u8; 96] = pk_bytes
                    .clone()
                    .try_into()
                    .map_err(|_| anyhow::format_err!("invalid 96-byte pubkey"))?;
                let opt_be = G1Affine::from_uncompressed_be(&bytes);
                let pt = if bool::from(opt_be.is_some()) {
                    opt_be.unwrap()
                } else {
                    let opt_le = G1Affine::from_uncompressed_le(&bytes);
                    if bool::from(opt_le.is_some()) {
                        opt_le.unwrap()
                    } else {
                        bail!("failed to deserialize 96-byte pubkey for signer {}", idx);
                    }
                };
                pt.to_compressed_be().to_vec()
            }
            other => bail!(
                "unexpected pubkey size {} for signer {} (expected 48 or 96)",
                other,
                idx
            ),
        };
        normalized.insert(idx, compressed);
    }
    Ok(normalized)
}

/// Variant discriminants for BlockKeeperSetChange enum (bincode u32).
const BK_CHANGE_ADDED: u32 = 0;
const BK_CHANGE_REMOVED: u32 = 1;

/// Parse a bk_set_update blob by scanning for pubkey markers.
///
/// Scans for the `u64(96)` pubkey length marker preceded by variant + signer_index.
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
            i += 14 + 96;
            continue;
        }
        i += 1;
    }
    results
}
