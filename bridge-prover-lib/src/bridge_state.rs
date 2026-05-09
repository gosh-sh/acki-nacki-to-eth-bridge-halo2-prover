//! Bridge state management for prover and verifier daemons.
//!
//! Both prover and verifier track the same logical state:
//! - Current layer historical hashes (up to 10)
//! - Seqno/block_id of last proved key block
//! - BK set Poseidon commitment (from node, not self-computed)

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// One layer hash entry in the bridge state.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LayerHashEntry {
    /// Layer number (1-based: 1..=10).
    pub layer_number: u8,
    /// Poseidon Merkle root hash for this layer (32 bytes LE).
    pub root_hash: [u8; 32],
    /// Seqno of the key block this hash was extracted from.
    pub from_block_seqno: u32,
}

/// Shared bridge state tracked by both prover and verifier.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BridgeState {
    /// Layer historical hashes (up to 10). Index 0 = layer 1.
    pub layer_hashes: Vec<LayerHashEntry>,
    /// Seqno of the last proved key block.
    pub last_key_block_seqno: u32,
    /// Block ID (8-leaf Merkle root) of the last proved key block.
    pub last_key_block_id: [u8; 32],
    /// BK set Poseidon commitment (from node, not self-computed).
    pub bk_set_poseidon_hash: [u8; 32],
    /// Whether initialization is complete (first key block seen).
    pub initialized: bool,
    /// Maximum number of layers ever seen (for detecting truly new layers vs re-appearances).
    #[serde(default)]
    pub max_layers_ever_seen: usize,
}

impl BridgeState {
    /// Create a new uninitialized state.
    pub fn new() -> Self {
        Self {
            layer_hashes: Vec::new(),
            last_key_block_seqno: 0,
            last_key_block_id: [0u8; 32],
            bk_set_poseidon_hash: [0u8; 32],
            initialized: false,
            max_layers_ever_seen: 0,
        }
    }

    /// Number of active layers.
    pub fn num_layers(&self) -> usize {
        self.layer_hashes.len()
    }

    /// Get the highest (oldest) layer hash — used as prev_max_level_layer_hash.
    pub fn highest_layer_hash(&self) -> Option<&[u8; 32]> {
        self.layer_hashes.last().map(|e| &e.root_hash)
    }

    /// Determine which prev_max_level_layer_hash to use for circuit 2,
    /// given the new key block has `new_num_layers` layers.
    ///
    /// Logic:
    /// - If new_num_layers >= old num_layers (t): use layer_hashes[t-1] (highest old layer)
    /// - If new_num_layers < old num_layers: use layer_hashes[new_num_layers - 1]
    pub fn prev_max_level_layer_hash_for(&self, new_num_layers: usize) -> [u8; 32] {
        let t = self.layer_hashes.len();
        if t == 0 {
            return [0u8; 32];
        }
        if new_num_layers >= t {
            self.layer_hashes[t - 1].root_hash
        } else {
            // Partial refresh: fewer layers in new block
            if new_num_layers > 0 {
                self.layer_hashes[new_num_layers - 1].root_hash
            } else {
                [0u8; 32]
            }
        }
    }

    /// Update state after a successful proof+verification of a key block.
    pub fn update(
        &mut self,
        new_layer_hashes: &[([u8; 32], u8)], // (root_hash, layer_number) pairs
        key_block_seqno: u32,
        key_block_id: [u8; 32],
        bk_set_poseidon_hash: [u8; 32],
    ) {
        // Update layer hashes: overwrite with new values, but KEEP old higher-layer
        // hashes that aren't in the new block. This is essential for L2 chain proofs
        // when intermediate blocks only have L1 (L2 appears every W^2 blocks).
        for (hash, layer_num) in new_layer_hashes {
            let idx = (*layer_num - 1) as usize;
            if idx < self.layer_hashes.len() {
                self.layer_hashes[idx] = LayerHashEntry {
                    layer_number: *layer_num,
                    root_hash: *hash,
                    from_block_seqno: key_block_seqno,
                };
            } else {
                // Extend to accommodate new layers
                while self.layer_hashes.len() < idx {
                    self.layer_hashes.push(LayerHashEntry {
                        layer_number: (self.layer_hashes.len() + 1) as u8,
                        root_hash: [0u8; 32],
                        from_block_seqno: key_block_seqno,
                    });
                }
                self.layer_hashes.push(LayerHashEntry {
                    layer_number: *layer_num,
                    root_hash: *hash,
                    from_block_seqno: key_block_seqno,
                });
            }
        }
        self.last_key_block_seqno = key_block_seqno;
        self.last_key_block_id = key_block_id;
        self.bk_set_poseidon_hash = bk_set_poseidon_hash;
        self.initialized = true;
        if self.layer_hashes.len() > self.max_layers_ever_seen {
            self.max_layers_ever_seen = self.layer_hashes.len();
        }
    }

    /// Load state from a JSON file (returns new state if file doesn't exist).
    pub fn load(path: &str) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::new());
        }
        let data = std::fs::read_to_string(path).context("failed to read state file")?;
        serde_json::from_str(&data).context("failed to parse state file")
    }

    /// Save state to a JSON file.
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
