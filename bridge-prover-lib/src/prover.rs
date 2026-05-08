use std::collections::HashMap;

use anyhow::Context;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::create_proof,
    poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK},
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use rand::rngs::OsRng;
use tracing::info;

use attestation_bls_checker_circuit::primary_circuit::PrimaryAttestationBlsCheckerCircuit;
use bridge_parsers::attestation_data_parser::{
    attestation_data_offset, parse_num_signers,
};

use crate::keys::{self, KeyManager};
use crate::poseidon::compute_bk_set_poseidon;

/// Output of a proof generation.
#[derive(Debug, Clone)]
pub struct ProofOutput {
    pub proof_bytes: Vec<u8>,
    pub block_id_fr: Fr,
    pub bk_set_commitment_fr: Fr,
    pub block_seq_no: u32,
    pub last_seen_block_seqno: u32,
}

/// Generate a primary attestation proof.
pub fn generate_primary_proof(
    key_manager: &KeyManager,
    attestation_bytes: &[u8],
    bk_set: &HashMap<u16, Vec<u8>>,
    last_seen_block_seqno: u32,
) -> anyhow::Result<ProofOutput> {
    let limb_bits = keys::circuit_limb_bits();
    let num_limbs = keys::circuit_num_limbs();

    // Compute expected public instances.
    let block_id_fr = compute_block_id_fr(attestation_bytes);
    let (bk_set_commitment_fr, _) = compute_bk_set_poseidon(bk_set);
    let block_seq_no = extract_block_seq_no(attestation_bytes);
    let block_seq_no_fr = Fr::from(block_seq_no as u64);
    let last_seen_fr = Fr::from(last_seen_block_seqno as u64);

    info!(
        "generating proof: block_seq_no={}, last_seen={}, bk_set_size={}",
        block_seq_no, last_seen_block_seqno, bk_set.len()
    );

    // Build circuit.
    let mut circuit = PrimaryAttestationBlsCheckerCircuit::<Fr>::new(
        attestation_bytes.to_vec(),
        bk_set.clone(),
        last_seen_block_seqno,
        keys::circuit_k() as usize,
        keys::circuit_num_unusable_rows(),
        keys::circuit_lookup_bits(),
        limb_bits,
        num_limbs,
        keys::circuit_max_signers(),
    );
    circuit.override_base_circuit_params(key_manager.primary_config().clone());

    // Generate proof.
    let instances = vec![block_id_fr, bk_set_commitment_fr, block_seq_no_fr, last_seen_fr];
    let instance_refs: &[&[Fr]] = &[&instances];
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(
        &key_manager.srs,
        key_manager.primary_pk(),
        &[circuit],
        &[instance_refs],
        OsRng,
        &mut transcript,
    )
    .context("proof generation failed")?;
    let proof_bytes = transcript.finalize();

    Ok(ProofOutput {
        proof_bytes,
        block_id_fr,
        bk_set_commitment_fr,
        block_seq_no,
        last_seen_block_seqno,
    })
}

/// Extract block_id as Fr from raw attestation bytes.
///
/// block_id is at offset 48 within AttestationData:
/// parent_block_id(40) + length_prefix(8) = 48, then 32 bytes of hash.
fn compute_block_id_fr(attestation_bytes: &[u8]) -> Fr {
    const BLOCK_ID_REL_OFFSET: usize = 48;

    let num_signers = parse_num_signers(attestation_bytes);
    let abs_offset = attestation_data_offset(num_signers) + BLOCK_ID_REL_OFFSET;
    let block_id_bytes = &attestation_bytes[abs_offset..abs_offset + 32];

    let mut result = Fr::zero();
    let mut power = Fr::one();
    let base = Fr::from(256u64);
    for &byte in block_id_bytes {
        result += Fr::from(byte as u64) * power;
        power *= base;
    }
    result
}

/// Extract block_seq_no (u32) from raw attestation bytes.
fn extract_block_seq_no(attestation_bytes: &[u8]) -> u32 {
    const BLOCK_SEQ_NO_REL_OFFSET: usize = 80;

    let num_signers = parse_num_signers(attestation_bytes);
    let abs_offset = attestation_data_offset(num_signers) + BLOCK_SEQ_NO_REL_OFFSET;
    let seqno_bytes = &attestation_bytes[abs_offset..abs_offset + 4];
    u32::from_le_bytes(seqno_bytes.try_into().unwrap())
}
