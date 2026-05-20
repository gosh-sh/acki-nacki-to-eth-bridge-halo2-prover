//! On-disk schema for the exported private witness JSON.
//!
//! Producers: `bridge-event-private-witness-export` (Rust binary + library),
//! eventually also the Python orchestration driver.
//! Consumers: `bridge_prover_lib::event_prover` (Track C), the future
//! `bridge-event-prover-daemon` (Track D).
//!
//! The schema is intentionally JSON-friendly: byte arrays are lowercase hex,
//! all integers fit in u64 or u128. Pinned `schema_version` so producer and
//! consumer can refuse mismatched runs the same way Phase 1 does for
//! `proof_*.json`.

use serde::{Deserialize, Serialize};

/// On-disk schema version. Bump whenever the JSON shape changes in a
/// non-backwards-compatible way.
pub const SCHEMA_VERSION: u32 = 1;

/// Top-level export record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateWitness {
    pub schema_version: u32,

    /// Hex repr_hash of the ExtOut message wrapper cell — primary identifier
    /// of this event.
    pub event_message_hash_hex: String,

    /// Block containing the emitted event message.
    pub block_id_hex: String,
    /// `seq_no` of the block above (for daemon-side anchor selection).
    pub block_seq_no: u64,

    /// Decoded event fields for human-readable diagnostics and to cross-check
    /// against the BOC walk. Not consumed by the circuit (the circuit
    /// rederives these from the raw bytes).
    pub event: WithdrawalInitiated,

    /// Flat 4-cell BFS walk of the ExtOut message DAG:
    /// `[wrapper, body, recipient, sender]`. Cell records here have exactly
    /// the layout `bridge-event-prove-circuit::boc_helper::BocFlattenData`
    /// expects.
    pub entries: [CellRecord; 4],

    /// Block-level context. The daemon (Track D) supplies these via the
    /// `BlockContext` overrides — the exporter on its own only knows what is
    /// in the ExtOut message BOC.
    pub block_context: BlockContext,

    /// Events-tree Merkle proof from this event's `ext_msg_leaf` to the
    /// block's `ext_out_messages_root`. `None` until populated by the daemon.
    pub events_tree_proof: Option<MerkleProofData>,

    /// Block-tree Merkle proof from this block's `block_leaf` to the
    /// history window's `root_1`. `None` until populated by the daemon.
    pub block_tree_proof: Option<MerkleProofData>,

    /// Anchor to a layer hash already verified by `bridge-verifier-daemon`.
    /// `None` until populated by the daemon.
    pub anchor: Option<AnchorRef>,
}

/// Mirror of `bridge-event-prove-circuit::boc_helper::BocFlattenData` with
/// serde derive. Field meanings are identical.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellRecord {
    /// 32-byte SHA-256 `repr_hash` of this cell, lowercase hex.
    pub repr_hash_hex: String,
    /// Number of child references (`refs_count`).
    pub refs_count: u8,
    /// For each child, the byte offset within `cell_repr_data` at which that
    /// child's repr_hash bytes begin. Absent when `refs_count == 0`.
    pub childs_repr_hashes_offset: Option<Vec<u16>>,
    /// SHA-256 preimage whose hash equals `repr_hash`, lowercase hex.
    pub cell_repr_data_hex: String,
}

/// Block-level context needed to anchor the event into the history Merkle
/// chain. The exporter cannot derive these from just the event BOC — they
/// must be supplied by the caller (daemon or CLI flags for testing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockContext {
    pub account_dapp_id_hex: String,
    pub account_id_hex: String,
    pub envelope_hash_hex: String,
}

/// Decoded `WithdrawalInitiated` event fields. All hex strings are
/// lowercase, big-endian byte order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalInitiated {
    /// 32 BE bytes (uint256). Stored as hex because Rust's `u128` is too
    /// narrow for the full ABI type, even though current fixtures all fit.
    pub dst_chain_id_hex: String,
    /// 16 BE bytes (uint128).
    pub amount_hex: String,
    /// 4 BE bytes (uint32).
    pub token_id: u32,
    /// 20 BE bytes (Ethereum address). Variable-length recipient support
    /// (up to 64 bytes) is documented as future work in the circuit's
    /// `EVENT_LAYOUT_COMPARISON.md` §5.6.
    pub recipient_hex: String,
}

/// Generic Merkle proof data — used for both the events tree and the
/// block tree (and the dense chain step proofs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofData {
    pub position: u32,
    /// Bottom-up sibling hashes, each 32 bytes hex.
    pub siblings_hex: Vec<String>,
}

/// Reference to a layer hash already mirrored by the verifier — the
/// "anchor" the event proof binds to. The daemon (Track D) populates this
/// from `state/verifier_state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRef {
    /// Which layer in `layer_windows` we chose (0 = L1, 1 = L2, ...).
    pub layer_idx: u32,
    /// Slot's `last_height` — for human verification.
    pub height: u64,
    /// Selected layer hash, 32 bytes hex.
    pub layer_hash_hex: String,
    /// Full vector of `NUM_LAYER_HASHES` candidates supplied as public
    /// instances; the circuit privately picks one via `hash_choice_index`.
    /// Length must equal `MAX_LAYERS * W` (80 at W=8).
    pub layer_hashes_public_hex: Vec<String>,
    /// Index into `layer_hashes_public_hex` of the chosen layer hash.
    pub hash_choice_index: u32,
    /// Dense chain (history window proof) — daemon-side artifact.
    pub dense_chain: Vec<DenseChainLinkSer>,
    /// How many of `dense_chain` are active (rest are inactive padding to
    /// `MAX_CHAIN_LEN`).
    pub num_active_chain_steps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenseChainLinkSer {
    pub active: bool,
    pub position: u32,
    pub siblings_hex: Vec<String>,
    pub leaf_hex: String,
}
