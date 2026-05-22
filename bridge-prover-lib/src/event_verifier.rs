//! Circuit 4 (Event Prove — `WithdrawalInitiated`) proof verification.

use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::verify_proof,
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::VerifierSHPLONK,
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
};

use crate::keys::KeyManager;

/// Verify a Circuit 4 proof against its public instances.
///
/// Instances layout (length `9 + NUM_LAYER_HASHES`):
///   `[token_id, amount, recipient_hi, recipient_lo, dst_chain_id,
///   sender_acc_fr, dapp_fr, acc_fr, nullifier,
///   layer_hashes[0..NUM_LAYER_HASHES]]`
///
/// Mirror of [`crate::layer_verifier::verify_layer_proof`] — the only
/// differences are which `KeyManager` VK is used (event VK) and the
/// instance count, which is checked implicitly by `verify_proof` against
/// the VK shape.
pub fn verify_event_proof(
    key_manager: &KeyManager,
    proof_bytes: &[u8],
    instances: &[Fr],
) -> bool {
    let instance_refs: &[&[Fr]] = &[instances];
    let verifier_params = key_manager.srs.verifier_params();
    let strategy = SingleStrategy::new(&key_manager.srs);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof_bytes);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        verifier_params,
        key_manager.event_vk(),
        strategy,
        &[instance_refs],
        &mut transcript,
    )
    .is_ok()
}
