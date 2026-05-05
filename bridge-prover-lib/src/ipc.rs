use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::prover::ProofOutput;

const PROOFS_DIR: &str = "proofs";

/// JSON structure for proof files written by the prover.
#[derive(Serialize, Deserialize, Debug)]
pub struct ProofRequest {
    pub block_seq_no: u32,
    pub last_seen_block_seqno: u32,
    pub envelope_hash_hex: String,
    pub proof_hex: String,
}

/// JSON structure for result files written by the verifier.
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyResult {
    pub block_seq_no: u32,
    pub verified: bool,
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

/// Write a proof output to the shared proofs directory.
pub fn write_proof(seq_no: u32, output: &ProofOutput) -> anyhow::Result<()> {
    ensure_proofs_dir();
    let request = ProofRequest {
        block_seq_no: output.block_seq_no,
        last_seen_block_seqno: output.last_seen_block_seqno,
        envelope_hash_hex: hex::encode(output.envelope_hash_fr.to_repr().as_ref()),
        proof_hex: hex::encode(&output.proof_bytes),
    };
    let json = serde_json::to_string_pretty(&request)?;
    std::fs::write(proof_file_path(seq_no), json)?;
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

/// Read a proof request file (used by verifier).
pub fn read_proof_request(seq_no: u32) -> anyhow::Result<ProofRequest> {
    let path = proof_file_path(seq_no);
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read proof file: {}", path))?;
    serde_json::from_str(&data).context("failed to parse proof request JSON")
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
