//! Circuit 4 (Event Prove — `WithdrawalInitiated`) proof generation.
//!
//! Track C in the Circuit 4 integration plan. Bridges the JSON schema
//! produced by `bridge-event-private-witness-export` (Track B) to the
//! `bridge-event-prove-circuit::BridgeEventProveCircuit` halo2 circuit
//! (Track A).
//!
//! Two responsibilities:
//!   1. **Input conversion** — deserialize the witness JSON, hex-decode
//!      cell records, and assemble a `BridgeEventProveCircuit` instance.
//!   2. **Public instance derivation** — build the
//!      `[token_id, dapp_fr, acc_fr, layer_hashes...]` instance vector
//!      the verifier will need.
//!
//! Keygen / real-prover plumbing is deliberately **not** wired in here yet.
//! The daemon (Track D) will own that — same on-demand PK loading pattern
//! `KeyManager` already uses for the primary and layer circuits. For now
//! we expose a `build_circuit` + `build_instances` API consumed by:
//!   * the MockProver integration test in `tests/event_prover.rs`
//!   * the future daemon, which will pass these into `create_proof`
//!
//! ### Anchor binding contract
//!
//! The witness's `anchor.layer_hashes_public_hex` array becomes the public
//! `layer_hashes` instance values. The circuit privately selects index
//! `anchor.hash_choice_index` and constrains the selected hash to equal
//! its computed `final_root`. The daemon must therefore guarantee:
//!   * `layer_hashes_public_hex.len() == NUM_LAYER_HASHES` (80 at W=8)
//!   * `layer_hashes_public_hex[hash_choice_index]` is the slot's actual
//!     hash that the prover's chain of Merkle proofs reaches.
//!
//! If those two invariants hold, the proof binds (privately) to a known
//! layer hash — providing the anonymity slice §1 of the bridge spec calls
//! for.

use std::convert::TryInto;

use anyhow::{bail, Context, Result};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::create_proof,
    poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK},
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use rand::rngs::OsRng;
use tracing::info;
use gosh_dense_balanced_tree::{bytes_to_fr, DenseChainLink, MAX_CHAIN_LEN};

use crate::keys::KeyManager;

use bridge_event_prove_circuit::boc_helper::BocFlattenData;
use bridge_event_prove_circuit::bridge_event_prove_circuit::{
    BridgeEventProveCircuit, MAX_EVENTS_TREE_DEPTH, NUM_LAYER_HASHES,
};

// Re-export so consumers can construct circuit params without an extra dep.
pub use halo2_base::gates::circuit::BaseCircuitParams;

// Re-export the witness JSON types so the daemon doesn't need to pull
// `bridge-event-private-witness-export` directly.
pub use bridge_event_private_witness_export::schema::{
    AnchorRef, BlockContext, CellRecord, DenseChainLinkSer, MerkleProofData,
    PrivateWitness, WithdrawalInitiated, SCHEMA_VERSION,
};

/// Conservative base-circuit params for first-cut Circuit 4 work. Mirrors
/// `bridge-event-prove-circuit::test_helpers::base_circuit_params`. Future
/// work: tighten as dark-dex did (K=14, ~110 advice columns).
pub fn default_event_circuit_params() -> BaseCircuitParams {
    BaseCircuitParams {
        k: 19,
        num_advice_per_phase: vec![16],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![2],
        lookup_bits: Some(18),
        num_instance_columns: 1,
    }
}

/// Bundle of everything the verifier needs once a Circuit 4 proof is generated.
pub struct EventProofInputs {
    pub circuit: BridgeEventProveCircuit,
    pub public_instances: Vec<Fr>,
}

/// Decode a hex byte string into a fixed-size byte array. The leading "0x"
/// prefix is tolerated.
fn parse_hex_array<const N: usize>(label: &str, s: &str) -> Result<[u8; N]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).with_context(|| format!("{label}: invalid hex"))?;
    if bytes.len() != N {
        bail!("{label}: expected {N} bytes, got {}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn cell_record_to_flat(rec: &CellRecord, label: &str) -> Result<BocFlattenData> {
    let repr_hash = parse_hex_array::<32>(&format!("{label}.repr_hash_hex"), &rec.repr_hash_hex)?;
    let cell_repr_data = hex::decode(&rec.cell_repr_data_hex)
        .with_context(|| format!("{label}.cell_repr_data_hex: invalid hex"))?;
    Ok(BocFlattenData {
        repr_hash,
        refs_count: rec.refs_count,
        childs_repr_hashes_offset: rec.childs_repr_hashes_offset.clone(),
        cell_repr_data,
    })
}

fn merkle_proof_to_native(proof: &MerkleProofData, label: &str) -> Result<(Vec<[u8; 32]>, usize)> {
    let mut siblings = Vec::with_capacity(proof.siblings_hex.len());
    for (i, s) in proof.siblings_hex.iter().enumerate() {
        siblings.push(parse_hex_array::<32>(
            &format!("{label}.siblings_hex[{i}]"),
            s,
        )?);
    }
    Ok((siblings, proof.position as usize))
}

fn dense_chain_to_native(links: &[DenseChainLinkSer]) -> Result<Vec<DenseChainLink>> {
    if links.len() != MAX_CHAIN_LEN {
        bail!(
            "anchor.dense_chain length {} != MAX_CHAIN_LEN ({MAX_CHAIN_LEN})",
            links.len(),
        );
    }
    let mut out = Vec::with_capacity(MAX_CHAIN_LEN);
    for (i, link) in links.iter().enumerate() {
        let leaf_native = parse_hex_array::<32>(&format!("dense_chain[{i}].leaf_hex"), &link.leaf_hex)?;
        let mut siblings = Vec::with_capacity(link.siblings_hex.len());
        for (j, s) in link.siblings_hex.iter().enumerate() {
            siblings.push(parse_hex_array::<32>(
                &format!("dense_chain[{i}].siblings_hex[{j}]"),
                s,
            )?);
        }
        out.push(DenseChainLink {
            active: link.active,
            siblings,
            position: link.position as usize,
            leaf_native,
        });
    }
    Ok(out)
}

/// Build a `BridgeEventProveCircuit` + public-instance vector from a fully
/// populated [`PrivateWitness`].
///
/// "Fully populated" means `events_tree_proof`, `block_tree_proof`, and
/// `anchor` are all `Some(_)` — the per-tx exporter leaves them `None` and
/// the daemon fills them in from verifier state.
pub fn build_proof_inputs(
    witness: &PrivateWitness,
    base_circuit_params: BaseCircuitParams,
) -> Result<EventProofInputs> {
    if witness.schema_version != SCHEMA_VERSION {
        bail!(
            "private witness schema_version={} but event_prover expects {SCHEMA_VERSION}",
            witness.schema_version,
        );
    }

    let entries_ref = &witness.entries;
    let entries: [BocFlattenData; 4] = [
        cell_record_to_flat(&entries_ref[0], "entries[0]")?,
        cell_record_to_flat(&entries_ref[1], "entries[1]")?,
        cell_record_to_flat(&entries_ref[2], "entries[2]")?,
        cell_record_to_flat(&entries_ref[3], "entries[3]")?,
    ];

    let events_tree = witness
        .events_tree_proof
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("events_tree_proof missing — daemon-side step not run"))?;
    let block_tree = witness
        .block_tree_proof
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("block_tree_proof missing — daemon-side step not run"))?;
    let anchor = witness
        .anchor
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("anchor missing — daemon-side step not run"))?;

    let (events_siblings, events_pos) = merkle_proof_to_native(events_tree, "events_tree_proof")?;
    if events_siblings.len() > MAX_EVENTS_TREE_DEPTH {
        bail!(
            "events_tree_proof depth {} exceeds MAX_EVENTS_TREE_DEPTH ({MAX_EVENTS_TREE_DEPTH})",
            events_siblings.len(),
        );
    }

    let (block_siblings, block_pos) = merkle_proof_to_native(block_tree, "block_tree_proof")?;

    let account_dapp_id = parse_hex_array::<32>(
        "block_context.account_dapp_id_hex",
        &witness.block_context.account_dapp_id_hex,
    )?;
    let account_id = parse_hex_array::<32>(
        "block_context.account_id_hex",
        &witness.block_context.account_id_hex,
    )?;
    let envelope_hash =
        parse_hex_array::<32>("block_context.envelope_hash_hex", &witness.block_context.envelope_hash_hex)?;
    let block_id = parse_hex_array::<32>("block_id_hex", &witness.block_id_hex)?;

    let dense_chain = dense_chain_to_native(&anchor.dense_chain)?;
    let num_active_chain_steps = anchor.num_active_chain_steps as usize;
    if num_active_chain_steps > MAX_CHAIN_LEN {
        bail!(
            "anchor.num_active_chain_steps={num_active_chain_steps} exceeds MAX_CHAIN_LEN ({MAX_CHAIN_LEN})",
        );
    }

    let layer_hashes = decode_layer_hashes(&anchor.layer_hashes_public_hex)?;
    let hash_choice_index = anchor.hash_choice_index as usize;
    if hash_choice_index >= NUM_LAYER_HASHES {
        bail!(
            "anchor.hash_choice_index={hash_choice_index} out of range [0, {NUM_LAYER_HASHES})"
        );
    }
    // Sanity-check the chosen slot matches the daemon's stated layer_hash_hex.
    let chosen = parse_hex_array::<32>("anchor.layer_hash_hex", &anchor.layer_hash_hex)?;
    let chosen_fr = bytes_to_fr(&chosen);
    if layer_hashes[hash_choice_index] != chosen_fr {
        bail!(
            "anchor.layer_hash_hex does not match layer_hashes_public_hex[{hash_choice_index}] — daemon supplied inconsistent anchor"
        );
    }

    let token_id_fr = derive_token_id_fr(&entries[1])?;
    let dapp_fr = bytes_to_fr(&account_dapp_id);
    let acc_fr = bytes_to_fr(&account_id);

    let mut public_instances = Vec::with_capacity(3 + NUM_LAYER_HASHES);
    public_instances.push(token_id_fr);
    public_instances.push(dapp_fr);
    public_instances.push(acc_fr);
    public_instances.extend_from_slice(&layer_hashes);

    let circuit = BridgeEventProveCircuit::new(
        entries,
        events_siblings,
        events_pos,
        account_dapp_id,
        account_id,
        block_id,
        envelope_hash,
        block_siblings,
        block_pos,
        dense_chain,
        num_active_chain_steps,
        layer_hashes,
        hash_choice_index,
        base_circuit_params,
    );

    Ok(EventProofInputs {
        circuit,
        public_instances,
    })
}

/// Decode `layer_hashes_public_hex` into `NUM_LAYER_HASHES` Fr elements
/// (little-endian byte order, same convention `bytes_to_fr` uses).
fn decode_layer_hashes(hex_list: &[String]) -> Result<Vec<Fr>> {
    if hex_list.len() != NUM_LAYER_HASHES {
        bail!(
            "anchor.layer_hashes_public_hex length {} != NUM_LAYER_HASHES ({NUM_LAYER_HASHES})",
            hex_list.len(),
        );
    }
    let mut out = Vec::with_capacity(NUM_LAYER_HASHES);
    for (i, s) in hex_list.iter().enumerate() {
        let bytes = parse_hex_array::<32>(&format!("layer_hashes_public_hex[{i}]"), s)?;
        out.push(bytes_to_fr(&bytes));
    }
    Ok(out)
}

/// Token ID is `BE_pack(body[54..58))` — same derivation as
/// `bridge_event_prove_circuit::bridge_event_prove_circuit::extract_event_public_fields`,
/// but accepting the decoded `BocFlattenData` directly so the caller doesn't
/// need to construct the full `[BocFlattenData; 4]` array twice.
fn derive_token_id_fr(body: &BocFlattenData) -> Result<Fr> {
    const TOKEN_ID_START: usize = 54;
    const TOKEN_ID_END: usize = 58;
    if body.cell_repr_data.len() < TOKEN_ID_END {
        bail!(
            "body cell payload too short ({} bytes) to extract tokenId",
            body.cell_repr_data.len(),
        );
    }
    let slice = &body.cell_repr_data[TOKEN_ID_START..TOKEN_ID_END];
    // BE-pack 4 bytes into Fr.
    let arr: [u8; 4] = slice.try_into().expect("checked length above");
    Ok(Fr::from(u32::from_be_bytes(arr) as u64))
}

/// Output of a Circuit 4 proof generation pass.
///
/// `proof_bytes` is the SHPLONK/Blake2b-encoded proof; `public_instances`
/// is the `[token_id, dapp_fr, acc_fr, layer_hashes...]` vector the verifier
/// (or the on-chain bridge) checks against.
#[derive(Clone)]
pub struct EventProofOutput {
    pub proof_bytes: Vec<u8>,
    pub public_instances: Vec<Fr>,
}

/// Generate a Circuit 4 proof from a fully-populated [`PrivateWitness`].
///
/// Caller is responsible for ensuring the event PK is loaded into memory
/// before calling — i.e. `key_manager.load_event_pk()?` first, then
/// `key_manager.unload_event_pk()` after. The same on-demand pattern
/// `bridge-prover-daemon` uses for the primary and layer PKs.
pub fn generate_event_proof(
    key_manager: &KeyManager,
    witness: &PrivateWitness,
) -> Result<EventProofOutput> {
    let inputs = build_proof_inputs(witness, key_manager.event_config().clone())
        .context("build_proof_inputs failed (translating witness JSON → circuit)")?;
    let EventProofInputs { circuit, public_instances } = inputs;
    generate_event_proof_from_circuit(key_manager, circuit, public_instances)
}

/// Lower-level entry point: prove an already-built [`BridgeEventProveCircuit`]
/// against its public instances. Used by the `--selftest` mode of the
/// `bridge-event-prove` binary, which gets its circuit from
/// `bridge-event-prove-circuit::test_helpers::build_synthetic_event_keygen_inputs`
/// rather than from a daemon-side [`PrivateWitness`].
pub fn generate_event_proof_from_circuit(
    key_manager: &KeyManager,
    circuit: BridgeEventProveCircuit,
    public_instances: Vec<Fr>,
) -> Result<EventProofOutput> {
    let instance_refs: &[&[Fr]] = &[&public_instances];
    info!(
        "generating Circuit 4 proof: {} public instances",
        public_instances.len()
    );

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
        key_manager.event_pk(),
        &[circuit],
        &[instance_refs],
        OsRng,
        &mut transcript,
    )
    .context("Circuit 4 proof generation failed")?;
    let proof_bytes = transcript.finalize();
    info!("Circuit 4 proof generated: {} bytes", proof_bytes.len());

    Ok(EventProofOutput {
        proof_bytes,
        public_instances,
    })
}
