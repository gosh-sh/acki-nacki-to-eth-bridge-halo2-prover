//! Parse attestation envelopes from a block's raw BOC (bincode Envelope<AckiNackiBlock>).
//!
//! The BOC is the base64-decoded `boc` field from the GraphQL block query.
//! Its structure is: `Envelope { aggregated_signature, signature_occurrences, data: AckiNackiBlock }`.
//! Inside the block data, the common section contains `block_attestations: Vec<Envelope<AttestationData>>`.
//! We scan for these nested envelopes by looking for the signature length marker (u64 = 192).

use std::collections::HashMap;

use anyhow::bail;

/// A parsed attestation envelope extracted from a block BOC.
#[derive(Debug, Clone)]
pub struct ParsedAttestation {
    pub raw_bytes: Vec<u8>,
    pub parent_block_id: [u8; 32],
    pub block_id: [u8; 32],
    pub block_seq_no: u32,
    pub envelope_hash: [u8; 32],
    pub target_type: u32, // 0 = Primary, 1 = Fallback
    pub signature_occurrences: HashMap<u16, u16>,
}

/// Extract all attestation envelopes from a block's raw BOC bytes.
///
/// The BOC is the base64-decoded `boc` field. We skip the outer Envelope header
/// (the block's own signature) and scan the remaining block data for nested
/// `Envelope<AttestationData>` structures identified by their 192-byte signature marker.
pub fn extract_attestations_from_boc(boc: &[u8]) -> anyhow::Result<Vec<ParsedAttestation>> {
    if boc.len() < 220 {
        bail!("BOC too short: {} bytes", boc.len());
    }

    // Skip the outer Envelope header (block's own attestation).
    // aggregated_signature: u64(len=192) + 192 bytes = 200
    let outer_sig_len = read_u64(boc, 0)?;
    if outer_sig_len != 192 {
        bail!("unexpected outer sig_len: {} (expected 192)", outer_sig_len);
    }
    let outer_num_occ = read_u64(boc, 200)?;
    if outer_num_occ > 100 {
        bail!("unexpected outer num_occurrences: {}", outer_num_occ);
    }
    let block_data_start = 200 + 8 + (outer_num_occ as usize) * 4;

    // Scan for nested attestation envelopes.
    let mut attestations = Vec::new();
    let mut pos = block_data_start;

    while pos + 220 < boc.len() {
        let val = read_u64(boc, pos).unwrap_or(0);
        if val == 192 {
            if let Ok(att) = try_parse_attestation_envelope(boc, pos) {
                let end = pos + att.raw_bytes.len();
                attestations.push(att);
                pos = end;
                continue;
            }
        }
        pos += 1;
    }

    Ok(attestations)
}

/// Try to parse an `Envelope<AttestationData>` at the given offset.
fn try_parse_attestation_envelope(data: &[u8], off: usize) -> anyhow::Result<ParsedAttestation> {
    let mut pos = off;

    // 1. aggregated_signature: u64(len=192) + 192 bytes
    let sig_len = read_u64(data, pos)?;
    if sig_len != 192 {
        bail!("sig_len != 192");
    }
    pos += 8;
    if pos + 192 > data.len() {
        bail!("truncated signature");
    }
    pos += 192;

    // 2. signature_occurrences: u64(count) + (u16, u16) entries
    let num_occ = read_u64(data, pos)? as usize;
    pos += 8;
    if num_occ == 0 || num_occ > 100 {
        bail!("invalid num_occurrences: {}", num_occ);
    }
    if pos + num_occ * 4 > data.len() {
        bail!("truncated occurrences");
    }
    let mut occurrences = HashMap::new();
    for _ in 0..num_occ {
        let idx = read_u16(data, pos)?;
        let cnt = read_u16(data, pos + 2)?;
        pos += 4;
        occurrences.insert(idx, cnt);
    }

    // 3. AttestationData:
    //    parent_block_id: serde_with::Bytes([u8;32]) = u64(32) + 32 bytes = 40
    //    block_id: same = 40
    //    block_seq_no: u32 LE = 4
    //    envelope_hash: transparent [u8;32] = 32
    //    target_type: u32 LE = 4
    //    Total data: 120 bytes

    // parent_block_id
    let pbi_len = read_u64(data, pos)?;
    if pbi_len != 32 {
        bail!("parent_block_id length != 32");
    }
    pos += 8;
    if pos + 32 > data.len() {
        bail!("truncated parent_block_id");
    }
    let mut parent_block_id = [0u8; 32];
    parent_block_id.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // block_id
    let bi_len = read_u64(data, pos)?;
    if bi_len != 32 {
        bail!("block_id length != 32");
    }
    pos += 8;
    if pos + 32 > data.len() {
        bail!("truncated block_id");
    }
    let mut block_id = [0u8; 32];
    block_id.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // block_seq_no
    if pos + 4 > data.len() {
        bail!("truncated block_seq_no");
    }
    let block_seq_no = read_u32(data, pos)?;
    pos += 4;

    // envelope_hash (transparent — 32 raw bytes, no length prefix)
    if pos + 32 > data.len() {
        bail!("truncated envelope_hash");
    }
    let mut envelope_hash = [0u8; 32];
    envelope_hash.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // target_type (u32 LE: 0 = Primary, 1 = Fallback)
    if pos + 4 > data.len() {
        bail!("truncated target_type");
    }
    let target_type = read_u32(data, pos)?;
    pos += 4;

    let raw_bytes = data[off..pos].to_vec();

    Ok(ParsedAttestation {
        raw_bytes,
        parent_block_id,
        block_id,
        block_seq_no,
        envelope_hash,
        target_type,
        signature_occurrences: occurrences,
    })
}

fn read_u64(data: &[u8], off: usize) -> anyhow::Result<u64> {
    if off + 8 > data.len() {
        bail!("read_u64: out of bounds at offset {}", off);
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}

fn read_u32(data: &[u8], off: usize) -> anyhow::Result<u32> {
    if off + 4 > data.len() {
        bail!("read_u32: out of bounds at offset {}", off);
    }
    Ok(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()))
}

fn read_u16(data: &[u8], off: usize) -> anyhow::Result<u16> {
    if off + 2 > data.len() {
        bail!("read_u16: out of bounds at offset {}", off);
    }
    Ok(u16::from_le_bytes(data[off..off + 2].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_known_attestation() {
        // Minimal test: construct a mock attestation envelope in bincode format.
        let mut buf = Vec::new();

        // aggregated_signature: u64(192) + 192 zero bytes
        buf.extend_from_slice(&192u64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 192]);

        // signature_occurrences: u64(2) + 2 entries
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // idx=0
        buf.extend_from_slice(&1u16.to_le_bytes()); // count=1
        buf.extend_from_slice(&1u16.to_le_bytes()); // idx=1
        buf.extend_from_slice(&1u16.to_le_bytes()); // count=1

        // parent_block_id: u64(32) + 32 bytes
        buf.extend_from_slice(&32u64.to_le_bytes());
        buf.extend_from_slice(&[0xAA; 32]);

        // block_id: u64(32) + 32 bytes
        buf.extend_from_slice(&32u64.to_le_bytes());
        buf.extend_from_slice(&[0xBB; 32]);

        // block_seq_no: u32
        buf.extend_from_slice(&42u32.to_le_bytes());

        // envelope_hash: 32 bytes (transparent)
        buf.extend_from_slice(&[0xCC; 32]);

        // target_type: u32 (0 = Primary)
        buf.extend_from_slice(&0u32.to_le_bytes());

        let att = try_parse_attestation_envelope(&buf, 0).unwrap();
        assert_eq!(att.block_seq_no, 42);
        assert_eq!(att.target_type, 0);
        assert_eq!(att.envelope_hash, [0xCC; 32]);
        assert_eq!(att.parent_block_id, [0xAA; 32]);
        assert_eq!(att.block_id, [0xBB; 32]);
        assert_eq!(att.signature_occurrences.len(), 2);
        assert_eq!(att.signature_occurrences[&0], 1);
        assert_eq!(att.signature_occurrences[&1], 1);
    }
}
