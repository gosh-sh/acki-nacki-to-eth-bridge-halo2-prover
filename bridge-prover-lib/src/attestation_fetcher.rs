//! Fetch attestations for a target block via GraphQL `Block.attestations[]`.
//!
//! The v3 gql-server exposes `Block.attestations[]` as a consumer-oriented view: the
//! resolver filters entries so each block's array contains attestations whose
//! inner `AttestationData.block_id` matches that block's own id — i.e. "the
//! attestation that signed THIS block". Behind the scenes the row still lives
//! in a later block's `common_section.block_attestations()`, but the GQL view
//! hides that and we just query block N directly.

use std::collections::HashMap;

use anyhow::Context;
use tracing::info;

use crate::gql_client::GqlClient;

/// An attestation envelope assembled from GraphQL fields on a later block's
/// `attestations[]` array.
///
/// `raw_bytes` is laid out exactly as `bincode(Envelope<AttestationData>)` so
/// `bridge_parsers::attestation_data_parser` and `prover.rs::compute_block_id_fr`
/// can index it with their fixed offsets.
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

/// Fetch the attestation envelope for block `target_seq_no` from GraphQL.
pub async fn fetch_attestation_for_block(
    client: &GqlClient,
    target_seq_no: u32,
) -> anyhow::Result<ParsedAttestation> {
    let mut att = client
        .query_attestation_envelope(target_seq_no as u64)
        .await
        .with_context(|| format!("query_attestation_envelope({target_seq_no})"))?;

    // The GraphQL `BlockAttestation` row doesn't expose block_seq_no; patch it
    // in here so downstream consumers (prover.rs::extract_block_seq_no) read
    // the correct value from raw_bytes.
    patch_seq_no_in_raw_bytes(&mut att, target_seq_no);
    att.block_seq_no = target_seq_no;

    info!(
        "attestation for seq={}: type={}, signers={:?}",
        target_seq_no,
        if att.target_type == 0 { "Primary" } else { "Fallback" },
        att.signature_occurrences,
    );

    Ok(att)
}

/// Overwrite the 4-byte block_seq_no slot inside `att.raw_bytes`. Layout:
/// `[0..200] = aggregated_signature`; `[200..208+N*4] = signature_occurrences`;
/// the attestation-data section begins at `208 + num_signers*4` and the
/// `block_seq_no` u32 sits at relative offset `80` within that section.
fn patch_seq_no_in_raw_bytes(att: &mut ParsedAttestation, seq_no: u32) {
    let num_signers: usize = att.signature_occurrences.values().map(|c| *c as usize).sum();
    let data_offset = 208 + num_signers * 4;
    let seq_off = data_offset + 80;
    if seq_off + 4 <= att.raw_bytes.len() {
        att.raw_bytes[seq_off..seq_off + 4].copy_from_slice(&seq_no.to_le_bytes());
    }
}
