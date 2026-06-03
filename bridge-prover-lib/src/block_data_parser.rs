//! Parser for the full serialized AckiNackiBlock (`data` field from GraphQL).
//!
//! The `data` field contains the bincode-serialized AckiNackiBlock:
//! ```text
//! [u64 BE: common_section_len]
//! [common_section_bytes...]      <- bincode(WrappedCommonSection)
//! [u64 BE: block_data_len]
//! [block_data_bytes...]          <- TVM block BOC
//! [u64 BE: tx_cnt]
//! [u64 BE: durable_diff_len]
//! [durable_diff_bytes...]
//! [32 bytes: hash]
//! ```
//!
//! Within common_section_bytes, we extract:
//! - history_proofs: BTreeMap<u8, ProofLayerRootHash>
//! - block_keeper_set_change_proof_data: Option<BlockKeeperSetChangeProofData>
//!   containing old/new BK set Poseidon hashes

use std::collections::BTreeMap;

use anyhow::bail;
use tracing::info;

/// Parsed block data from the `data` field.
#[derive(Debug, Clone)]
pub struct ParsedBlockData {
    /// Raw common section bytes (for L1 = SHA-256).
    pub common_section_bytes: Vec<u8>,
    /// TVM block BOC bytes (for L4 = repr_hash of the root cell).
    pub tvm_block_boc: Vec<u8>,
    /// Transaction count.
    pub tx_cnt: u64,
    /// Durable state diff bytes (for L5 = SHA-256).
    pub durable_state_bytes: Vec<u8>,
    /// Block hash (32 bytes, appended at end of serialization).
    pub block_hash: [u8; 32],
    /// History proofs extracted from common section.
    /// Map: layer_number (u8) → root_hash ([u8; 32]).
    pub history_proofs: BTreeMap<u8, [u8; 32]>,
    /// Old BK set Poseidon hash (from block_keeper_set_change_proof_data).
    pub old_bk_set_hash: Option<[u8; 32]>,
    /// New BK set Poseidon hash (from block_keeper_set_change_proof_data).
    pub new_bk_set_hash: Option<[u8; 32]>,
}

/// Parse the AckiNackiBlock `data` field (base64-decoded bytes).
///
/// Format:
/// ```text
/// [u64 LE: total_raw_len]    <- bincode serialize_bytes header
/// [u64 BE: cs_len][cs_bytes] <- common section
/// [u64 BE: block_len][block] <- TVM block BOC
/// [u64 BE: tx_cnt]
/// [u64 BE: diff_len][diff]   <- durable state diff
/// [32 bytes: hash]
/// ```
pub fn parse_block_data(data: &[u8]) -> anyhow::Result<ParsedBlockData> {
    if data.len() < 8 + 8 + 8 + 8 + 8 + 32 {
        bail!("data too short: {} bytes", data.len());
    }

    // Skip the bincode serialize_bytes header (u64 LE total length).
    let total_raw_len = read_u64_le(data, 0)? as usize;
    if 8 + total_raw_len > data.len() {
        bail!(
            "total_raw_len={} exceeds data length={} (after 8-byte header)",
            total_raw_len,
            data.len() - 8
        );
    }
    let mut pos = 8;

    // 1. Common section: [u64 BE: len][bytes]
    let cs_len = read_u64_be(data, pos)? as usize;
    pos += 8;
    if pos + cs_len > data.len() {
        bail!(
            "common_section_len={} exceeds data length={} at pos={}",
            cs_len,
            data.len(),
            pos
        );
    }
    let common_section_bytes = data[pos..pos + cs_len].to_vec();
    pos += cs_len;

    // 2. Block data: [u64 BE: len][bytes]
    let block_len = read_u64_be(data, pos)? as usize;
    pos += 8;
    if pos + block_len > data.len() {
        bail!(
            "block_data_len={} exceeds data length={} at pos={}",
            block_len,
            data.len(),
            pos
        );
    }
    let tvm_block_boc = data[pos..pos + block_len].to_vec();
    pos += block_len;

    // 3. tx_cnt: [u64 BE]
    let tx_cnt = read_u64_be(data, pos)?;
    pos += 8;

    // 4. Durable diff: [u64 BE: len][bytes]
    let diff_len = read_u64_be(data, pos)? as usize;
    pos += 8;
    if pos + diff_len > data.len() {
        bail!(
            "durable_diff_len={} exceeds data length={} at pos={}",
            diff_len,
            data.len(),
            pos
        );
    }
    let durable_state_bytes = data[pos..pos + diff_len].to_vec();
    pos += diff_len;

    // 5. Hash: [32 bytes]
    if pos + 32 > data.len() {
        bail!("no room for 32-byte hash at pos={}", pos);
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&data[pos..pos + 32]);

    info!(
        "parsed block data: cs_len={}, block_len={}, tx_cnt={}, diff_len={}, total={}",
        cs_len,
        block_len,
        tx_cnt,
        diff_len,
        data.len()
    );

    // 6. Extract history_proofs and proof_data from common section.
    let (history_proofs, old_bk_set_hash, new_bk_set_hash) =
        extract_proofs_from_common_section(&common_section_bytes);

    Ok(ParsedBlockData {
        common_section_bytes,
        tvm_block_boc,
        tx_cnt,
        durable_state_bytes,
        block_hash,
        history_proofs,
        old_bk_set_hash,
        new_bk_set_hash,
    })
}

/// Extract history_proofs and BK set hashes from the common section bytes.
///
/// Since the common section is bincode-serialized WrappedCommonSection with many fields,
/// we use a pattern-scanning approach to find the proof data structures.
///
/// The BK set Poseidon hashes are two consecutive [u8; 32] values within
/// BlockKeeperSetTransitionHashes. We search for them near the end of the
/// common section where block_keeper_set_change_proof_data lives.
///
/// History proofs is a BTreeMap<u8, ProofLayerRootHash>. Each ProofLayerRootHash has:
/// - layer: u8
/// - root_hash: [u8; 32]
/// - block_height: BlockHeight (thread_id + u64)
/// - block_id: BlockIdentifier ([u8; 32])
fn extract_proofs_from_common_section(
    cs: &[u8],
) -> (BTreeMap<u8, [u8; 32]>, Option<[u8; 32]>, Option<[u8; 32]>) {
    let mut history_proofs = BTreeMap::new();
    let mut old_bk_hash = None;
    let mut new_bk_hash = None;

    // Strategy: scan backwards from the end of common section.
    // block_keeper_set_change_proof_data is the LAST field.
    // It starts with Option discriminant (0x00 = None, 0x01 = Some).
    //
    // When Some, it contains:
    //   BlockKeeperSetTransitionHashes:
    //     old_bk_set_hash: [u8; 32]
    //     new_bk_set_hash: [u8; 32]
    //   history_proof_layer_hashes: BTreeMap<u8, (BlockHeight, [u8; 32])>
    //
    // Before that is tracked_ext_out_messages (HashMap), tracked_ext_out_messages_root ([u8; 32]),
    // and history_proofs (BTreeMap<u8, ProofLayerRootHash>).

    // Try to find proof_data by scanning for the Option<Some> discriminant followed by
    // two 32-byte hashes (which are Poseidon hashes — typically non-zero, non-trivial values).
    //
    // We scan from the end backwards looking for a reasonable structure.
    if cs.len() < 100 {
        return (history_proofs, old_bk_hash, new_bk_hash);
    }

    // Approach: try to find block_keeper_set_change_proof_data near the end.
    // Scan backward for Option::Some (0x01) followed by 64 bytes (two hashes).
    for scan_pos in (0..cs.len().saturating_sub(65)).rev() {
        if cs[scan_pos] == 0x01 {
            // Potential Option::Some. Next 32 bytes = old_bk_set_hash, then 32 = new_bk_set_hash.
            let after = scan_pos + 1;
            if after + 64 <= cs.len() {
                let mut candidate_old = [0u8; 32];
                let mut candidate_new = [0u8; 32];
                candidate_old.copy_from_slice(&cs[after..after + 32]);
                candidate_new.copy_from_slice(&cs[after + 32..after + 64]);

                // Heuristic: both hashes should be non-zero and high byte should be
                // small (Poseidon Fr values have top byte < 0x30 typically).
                let old_ok = candidate_old != [0u8; 32] && candidate_old[31] < 0x40;
                let new_ok = candidate_new != [0u8; 32] && candidate_new[31] < 0x40;

                if old_ok && new_ok {
                    old_bk_hash = Some(candidate_old);
                    new_bk_hash = Some(candidate_new);
                    info!(
                        "found BK set hashes at offset {}: old={}, new={}",
                        scan_pos,
                        hex::encode(candidate_old),
                        hex::encode(candidate_new)
                    );

                    // After the two hashes, there's a BTreeMap<u8, (BlockHeight, [u8; 32])>.
                    // And BEFORE scan_pos, there should be history_proofs and other fields.
                    break;
                }
            }
        }
    }

    // Try to find history_proofs BTreeMap somewhere in the common section.
    // It's serialized as: [u64 LE: count] then entries.
    // Each entry: [u8: key (layer_num)] + ProofLayerRootHash
    //   ProofLayerRootHash: [u8: layer] [u8;32: root_hash] [BlockHeight: thread_id bytes + u64] [u8;32: block_id]
    //
    // We look for small BTreeMap counts (1-10) with valid layer numbers.
    for scan_pos in 0..cs.len().saturating_sub(50) {
        if let Ok(count) = read_u64_le(cs, scan_pos) {
            if count >= 1 && count <= 10 {
                // Try to parse `count` entries starting after the u64.
                if let Some(proofs) = try_parse_history_proofs(cs, scan_pos + 8, count as usize) {
                    if !proofs.is_empty() {
                        info!(
                            "found {} history_proofs at offset {}: layers={:?}",
                            proofs.len(),
                            scan_pos,
                            proofs.keys().collect::<Vec<_>>()
                        );
                        history_proofs = proofs;
                        break;
                    }
                }
            }
        }
    }

    (history_proofs, old_bk_hash, new_bk_hash)
}

/// Try to parse `count` ProofLayerRootHash entries starting at `pos`.
///
/// Each BTreeMap entry is: [u8 key] + ProofLayerRootHash.
/// ProofLayerRootHash: [u8 layer] [u8;32 root_hash] [BlockHeight] [BlockIdentifier(u8;32)]
///
/// BlockHeight = ThreadIdentifier + u64 height.
/// ThreadIdentifier's bincode size is not known statically — it depends on the
/// number of fields in the struct. We detect the entry size dynamically:
///
/// For count >= 2: scan forward from the first entry's root_hash to find where
/// [key=2, layer=2] appears, which gives us the exact entry size.
///
/// For count == 1: scan for the next recognizable structure boundary.
fn try_parse_history_proofs(cs: &[u8], start: usize, count: usize) -> Option<BTreeMap<u8, [u8; 32]>> {
    // First entry must start with key=1, layer=1.
    if start + 34 > cs.len() {
        return None;
    }
    let key0 = cs[start];
    let layer0 = cs[start + 1];
    if key0 != 1 || layer0 != 1 {
        return None;
    }

    let mut root_hash_0 = [0u8; 32];
    root_hash_0.copy_from_slice(&cs[start + 2..start + 34]);
    if root_hash_0 == [0u8; 32] {
        return None;
    }

    // Detect entry_size by finding entry 2 (if count >= 2).
    let entry_size = if count >= 2 {
        let mut detected = None;
        // The gap after root_hash contains BlockHeight + BlockIdentifier.
        // Scan for [key=2, layer=2] followed by a non-zero 32-byte hash.
        for offset in 40..200 {
            let candidate_start = start + offset;
            if candidate_start + 34 > cs.len() {
                break;
            }
            if cs[candidate_start] == 2 && cs[candidate_start + 1] == 2 {
                let hash = &cs[candidate_start + 2..candidate_start + 34];
                if hash != &[0u8; 32] {
                    detected = Some(offset); // entry_size = offset from start of entry 1 to start of entry 2
                    break;
                }
            }
        }
        match detected {
            Some(s) => s,
            None => return None,
        }
    } else {
        // count == 1: we only need the root_hash, skip the rest.
        // Use a dummy entry_size — we won't parse beyond entry 1.
        0
    };

    // Now parse all entries using the detected entry_size.
    let mut proofs = BTreeMap::new();
    for i in 0..count {
        let entry_start = start + i * entry_size;
        if entry_start + 34 > cs.len() {
            return None;
        }

        let key_layer = cs[entry_start];
        let layer = cs[entry_start + 1];

        // Both layer values should match, be in 1..=10, and be consecutive.
        if key_layer != layer || layer != (i as u8 + 1) {
            return None;
        }

        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&cs[entry_start + 2..entry_start + 34]);
        if root_hash == [0u8; 32] {
            return None;
        }

        proofs.insert(layer, root_hash);
    }

    Some(proofs)
}

fn read_u64_be(data: &[u8], off: usize) -> anyhow::Result<u64> {
    if off + 8 > data.len() {
        bail!("read_u64_be: out of bounds at offset {}", off);
    }
    Ok(u64::from_be_bytes(data[off..off + 8].try_into().unwrap()))
}

fn read_u64_le(data: &[u8], off: usize) -> anyhow::Result<u64> {
    if off + 8 > data.len() {
        bail!("read_u64_le: out of bounds at offset {}", off);
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}
