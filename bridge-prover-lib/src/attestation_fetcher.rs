//! Fetch attestations from a node's block BOC data via GraphQL.

use anyhow::bail;
use tracing::info;

use crate::gql_client::GqlClient;

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
            source_seq,
            &source_hash[..12.min(source_hash.len())],
            target_seq_no
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
