//! 8-leaf SHA-256 Merkle tree for block ID computation.
//!
//! Reconstructs the block_id and extracts Merkle siblings needed by Circuit 2.
//!
//! Tree structure:
//! ```text
//!                        Root (= block_id)
//!                       /                  \
//!                  H_01                      H_23
//!                 /     \                  /      \
//!              H_0       H_1           H_2        H_3
//!             /   \     /   \         /   \      /   \
//!           L0    L1   L2   L3      L4    L5   L6    L7
//! ```
//!
//! Leaf values:
//! - L0: Poseidon(layer_hashes_preimage)  — 331 bytes split into 31-byte Fr chunks
//! - L1: SHA-256(common_section_bytes)
//! - L2: old_bk_set_poseidon_hash (32 bytes LE)
//! - L3: new_bk_set_poseidon_hash (32 bytes LE)
//! - L4: tvm_block_repr_hash
//! - L5: SHA-256(durable_state_bytes)
//! - L6: SHA-256(tx_cnt as u64 big-endian)
//! - L7: [0u8; 32]

use sha2::{Digest, Sha256};

/// SHA-256(left || right) for Merkle internal nodes.
fn sha256_combine(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// SHA-256 of arbitrary bytes.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// All data for the 8-leaf block ID Merkle tree.
#[derive(Clone, Debug)]
pub struct BlockIdMerkleTree {
    pub leaves: [[u8; 32]; 8],
    pub h0: [u8; 32],
    pub h1: [u8; 32],
    pub h2: [u8; 32],
    pub h3: [u8; 32],
    pub h01: [u8; 32],
    pub h23: [u8; 32],
    pub root: [u8; 32],
}

impl BlockIdMerkleTree {
    /// Build from 8 leaf values.
    pub fn from_leaves(leaves: [[u8; 32]; 8]) -> Self {
        let h0 = sha256_combine(&leaves[0], &leaves[1]);
        let h1 = sha256_combine(&leaves[2], &leaves[3]);
        let h2 = sha256_combine(&leaves[4], &leaves[5]);
        let h3 = sha256_combine(&leaves[6], &leaves[7]);
        let h01 = sha256_combine(&h0, &h1);
        let h23 = sha256_combine(&h2, &h3);
        let root = sha256_combine(&h01, &h23);
        Self { leaves, h0, h1, h2, h3, h01, h23, root }
    }

    /// Merkle siblings for Circuit 2 (leaf L0): [L1, H_1, H_23].
    pub fn siblings_for_l0(&self) -> [[u8; 32]; 3] {
        [self.leaves[1], self.h1, self.h23]
    }

    /// Block ID = root of the tree.
    pub fn block_id(&self) -> [u8; 32] {
        self.root
    }
}

/// Compute the full block ID Merkle tree from its components.
///
/// Returns the tree with all internal nodes and the block_id (root).
pub fn compute_block_id_tree(
    layer_hashes_preimage: &[u8],
    common_section_bytes: &[u8],
    old_bk_set_hash: &[u8; 32],
    new_bk_set_hash: &[u8; 32],
    tvm_block_repr_hash: &[u8; 32],
    durable_state_bytes: &[u8],
    tx_cnt: u64,
) -> BlockIdMerkleTree {
    // L0: Poseidon hash of layer_hashes_preimage (331 bytes → 11 Fr chunks → Poseidon)
    let l0_bytes = bridge_poseidon::poseidon_hash_bytes(layer_hashes_preimage);
    let mut l0 = [0u8; 32];
    l0.copy_from_slice(&l0_bytes);

    // L1: SHA-256(common_section_bytes)
    let l1 = sha256_hash(common_section_bytes);

    // L2: old BK set Poseidon commitment (already 32 bytes)
    let l2 = *old_bk_set_hash;

    // L3: new BK set Poseidon commitment
    let l3 = *new_bk_set_hash;

    // L4: TVM block representation hash
    let l4 = *tvm_block_repr_hash;

    // L5: SHA-256(durable_state_bytes)
    let l5 = sha256_hash(durable_state_bytes);

    // L6: SHA-256(tx_cnt as u64 big-endian)
    let l6 = sha256_hash(&tx_cnt.to_be_bytes());

    // L7: zero padding
    let l7 = [0u8; 32];

    BlockIdMerkleTree::from_leaves([l0, l1, l2, l3, l4, l5, l6, l7])
}

/// Build a 331-byte layer hashes preimage from layer root hashes.
///
/// Format: [num_layers: u8] + 10 * [layer_number: u8, root_hash: [u8; 32]]
pub fn build_layer_hashes_preimage(
    num_layers: usize,
    root_hashes: &[[u8; 32]],
) -> [u8; 331] {
    assert!(num_layers <= 10);
    assert!(root_hashes.len() >= num_layers);

    let mut preimage = [0u8; 331];
    preimage[0] = num_layers as u8;

    for i in 0..10 {
        let offset = 1 + i * 33;
        preimage[offset] = (i + 1) as u8; // layer_number = i+1
        if i < num_layers {
            preimage[offset + 1..offset + 1 + 32].copy_from_slice(&root_hashes[i]);
        }
        // Inactive layers remain zero
    }

    preimage
}
