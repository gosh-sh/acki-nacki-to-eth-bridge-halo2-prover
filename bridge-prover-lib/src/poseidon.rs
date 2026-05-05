use std::collections::HashMap;

use gosh_bls_verification::helpers::deserialize_g1_pubkey;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use pse_poseidon::Poseidon;

// Must match the constants in attestation-bls-checker-circuit/src/lib.rs.
pub const POSEIDON_T: usize = 3;
pub const POSEIDON_RATE: usize = 2;
pub const POSEIDON_R_F: usize = 8;
pub const POSEIDON_R_P: usize = 57;
pub const PADDING_SIGNER_INDEX: u16 = 0xFFFF;
pub const MAX_SIGNERS: usize = 300;

/// Compute the Poseidon commitment of a BK set, matching the in-circuit computation.
///
/// Always hashes exactly MAX_SIGNERS entries. Real entries use the pubkey's
/// x-coordinate CRT limbs; padding entries use PADDING_SIGNER_INDEX and zero x-limbs.
pub fn compute_bk_set_poseidon(
    bk_set: &HashMap<u16, Vec<u8>>,
    limb_bits: usize,
    num_limbs: usize,
) -> Fr {
    let mut sorted_keys: Vec<u16> = bk_set.keys().cloned().collect();
    sorted_keys.sort();
    let actual_size = sorted_keys.len();

    let limb_mask = (num_bigint::BigUint::from(1u64) << limb_bits) - 1u64;
    let mut poseidon_input: Vec<Fr> = Vec::with_capacity(MAX_SIGNERS * (1 + num_limbs));

    for k in 0..MAX_SIGNERS {
        if k < actual_size {
            let idx = sorted_keys[k];
            poseidon_input.push(Fr::from(idx as u64));

            let pk_bytes = &bk_set[&idx];
            let g1 = deserialize_g1_pubkey(pk_bytes);
            let x_bytes_le = g1.x.to_bytes();
            let x_bigint = num_bigint::BigUint::from_bytes_le(&x_bytes_le);

            for i in 0..num_limbs {
                let limb_val = (&x_bigint >> (i * limb_bits)) & &limb_mask;
                let limb_bytes = limb_val.to_bytes_le();
                let mut buf = [0u8; 32];
                let len = limb_bytes.len().min(32);
                buf[..len].copy_from_slice(&limb_bytes[..len]);
                poseidon_input.push(Fr::from_repr(buf).unwrap());
            }
        } else {
            poseidon_input.push(Fr::from(PADDING_SIGNER_INDEX as u64));
            for _ in 0..num_limbs {
                poseidon_input.push(Fr::zero());
            }
        }
    }

    let mut sponge = Poseidon::<Fr, POSEIDON_T, POSEIDON_RATE>::new(POSEIDON_R_F, POSEIDON_R_P);
    sponge.update(&poseidon_input);
    sponge.squeeze()
}
