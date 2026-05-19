//! File-based IPC for proof exchange between prover and verifier daemons.
//!
//! Supports both Circuit 1a (primary attestation) and Circuit 2 (layer hashes).

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use serde::{Deserialize, Serialize};

const PROOFS_DIR: &str = "proofs";

/// Current `ProofRequest` schema version. Bumped to 2 when `block_height` was
/// added; the verifier rejects mismatched versions instead of silently
/// re-interpreting fields.
pub const PROOF_REQUEST_SCHEMA_VERSION: u32 = 2;

fn default_schema_version() -> u32 { PROOF_REQUEST_SCHEMA_VERSION }

/// JSON structure for combined proof files (Circuit 1a + Circuit 2).
#[derive(Serialize, Deserialize, Debug)]
pub struct ProofRequest {
    /// Wire-format version. v2 added `block_height`. Older (v1) files
    /// implicitly map to `schema_version = 1` via `#[serde(default = ...)]`
    /// but only after they're shaped to fit — see `read_proof_request`.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

    /// Key block sequence number.
    pub block_seq_no: u32,
    /// Thread-anchored `BlockHeight.height` of the key block. In Acki Nacki
    /// `height` resets on thread crossings, so it is NOT interchangeable with
    /// `block_seq_no` in multi-thread chains. This is the value the contract
    /// mirror's per-layer `heights[W]` slot stores.
    pub block_height: u64,
    /// Sequence number of the previously proved key block.
    pub last_seen_block_seqno: u32,
    /// Block ID from Circuit 1a (attestation) as hex Fr.
    pub block_id_hex: String,

    // ---- Circuit 1a (Primary Attestation) ----
    /// Hex-encoded Circuit 1a proof bytes.
    pub primary_proof_hex: String,

    // ---- Circuit 2 (Layer Hashes Movement) ----
    /// Hex-encoded Circuit 2 proof bytes.
    pub layer_proof_hex: String,
    /// Block ID from Circuit 2 (Merkle tree root) as hex Fr.
    pub layer_block_id_hex: String,
    /// BK set Poseidon commitment (from node) as hex Fr.
    pub bk_set_poseidon_hash_hex: String,
    /// Number of active layers (1..=10).
    pub num_layers: u8,
    /// Layer hash Fr values (10 entries, inactive = zero Fr) as hex.
    pub layer_hash_frs_hex: Vec<String>,
    /// Previous max-level layer hash as hex Fr.
    pub prev_max_level_layer_hash_hex: String,
}

/// JSON structure for verification result files.
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyResult {
    pub block_seq_no: u32,
    pub primary_verified: bool,
    pub layer_verified: bool,
    pub error: Option<String>,
}

pub fn proof_file_path(seq_no: u32) -> String {
    format!("{}/proof_{:06}.json", PROOFS_DIR, seq_no)
}

pub fn result_file_path(seq_no: u32) -> String {
    format!("{}/result_{:06}.json", PROOFS_DIR, seq_no)
}

pub fn ensure_proofs_dir() {
    std::fs::create_dir_all(PROOFS_DIR).ok();
}

/// Write a combined proof (Circuit 1a + Circuit 2) for the verifier.
pub fn write_combined_proof(request: &ProofRequest) -> anyhow::Result<()> {
    ensure_proofs_dir();
    let json = serde_json::to_string_pretty(request)?;
    std::fs::write(proof_file_path(request.block_seq_no), json)?;
    Ok(())
}

/// Wait for a verifier result file to appear.
pub async fn wait_for_result(seq_no: u32, timeout: Duration) -> anyhow::Result<VerifyResult> {
    let path = result_file_path(seq_no);
    let start = std::time::Instant::now();
    loop {
        if Path::new(&path).exists() {
            let data = std::fs::read_to_string(&path).context("failed to read result file")?;
            return serde_json::from_str(&data).context("failed to parse result JSON");
        }
        if start.elapsed() > timeout {
            anyhow::bail!("timeout waiting for verifier result for seq_no={}", seq_no);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Read a proof request file (used by verifier). Rejects schema versions the
/// daemon was not built for — a mismatch almost certainly means the prover
/// and verifier are on different commits, which would silently mis-mirror
/// state if we just re-interpreted fields.
pub fn read_proof_request(seq_no: u32) -> anyhow::Result<ProofRequest> {
    let path = proof_file_path(seq_no);
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read proof file: {}", path))?;
    let req: ProofRequest = serde_json::from_str(&data)
        .context("failed to parse proof request JSON")?;
    if req.schema_version != PROOF_REQUEST_SCHEMA_VERSION {
        anyhow::bail!(
            "proof file {} has schema_version={} but verifier expects {}",
            path,
            req.schema_version,
            PROOF_REQUEST_SCHEMA_VERSION
        );
    }
    Ok(req)
}

/// Write a verification result (used by verifier).
pub fn write_result(result: &VerifyResult) -> anyhow::Result<()> {
    ensure_proofs_dir();
    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(result_file_path(result.block_seq_no), json)?;
    Ok(())
}

/// Parse an Fr from a hex string (32-byte LE representation).
pub fn fr_from_hex(hex_str: &str) -> anyhow::Result<Fr> {
    let bytes = hex::decode(hex_str).context("invalid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32 bytes for Fr, got {}", bytes.len());
    }
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes);
    Option::from(Fr::from_repr(repr)).ok_or_else(|| anyhow::format_err!("invalid Fr repr"))
}

/// Encode an Fr value as hex string (32-byte LE representation).
pub fn fr_to_hex(fr: &Fr) -> String {
    hex::encode(fr.to_repr().as_ref())
}
