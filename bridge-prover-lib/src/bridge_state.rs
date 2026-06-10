//! Bridge state — full mirror of the on-chain `GlobalHistoryData`.
//!
//! Both prover and verifier daemons hold this exact same shape so that the
//! verifier's view is a byte-for-byte mirror of what the Ethereum contract
//! would store. See `bridge-event-prove-circuit/README.md` ("Full Contract
//! Sketch") for the Solidity-side reference.
//!
//! Per-layer rolling window of width `W = HISTORY_PROOF_WINDOW_SIZE`:
//!   * `data[W]`       — most recent layer-root hashes (circular buffer)
//!   * `heights[W]`    — block heights matching each slot (parallel to `data`)
//!   * `data_len`      — number of valid entries (saturates at W)
//!   * `write_cursor`  — next slot to overwrite (always `mod W`)
//!   * `last_height`   — height of the most recently appended hash
//!
//! `data_len` and `write_cursor` are both kept (rather than just one counter
//! mod W) so callers can tell a half-full window from a full one without
//! scanning, and so `flatten_layer_hashes` can stream slots in chronological
//! order even before the window fills.

use std::collections::VecDeque;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Layers are 1-indexed (1..=MAX_LAYERS); slot 0 of `layer_windows` is layer 1.
pub const MAX_LAYERS: usize = 10;

/// Cap on the `BridgeState::recent_bundles` ring. Keeps the state file small
/// while preserving enough history for an orchestrator to confirm a recent
/// run of self-verified bundles.
pub const RECENT_BUNDLES_CAP: usize = 16;

/// Per-bundle self-verification outcome recorded by `bridge-prover-daemon`
/// after it generates and locally verifies its own Circuit 1a + Circuit 2
/// proofs. Surfaced via `prover_state.json` so an external orchestrator can
/// poll it without launching a verifier daemon.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BundleResult {
    /// Thinned key block seq_no this result is for.
    pub key_block_seq_no: u64,
    /// Circuit 1a self-verify passed.
    pub primary_ok: bool,
    /// Circuit 2 self-verify passed.
    pub layer_ok: bool,
    /// Convenience: `primary_ok && layer_ok`.
    pub verify_ok: bool,
    /// Unix epoch seconds when the result was recorded.
    pub ts_unix: u64,
}

/// Per-layer rolling window. `data.len() == heights.len() == window_size`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HistoryWindow {
    /// Slot buffer of length `W`. Unused slots are zero.
    pub data: Vec<[u8; 32]>,
    /// Parallel slot buffer for the block heights that produced each hash.
    pub heights: Vec<u64>,
    /// Number of valid entries currently in the window (saturates at `W`).
    pub data_len: usize,
    /// Next slot index to overwrite (always `mod W`).
    pub write_cursor: usize,
    /// Height of the last appended hash. Zero when the window is empty.
    pub last_height: u64,
}

impl HistoryWindow {
    /// Create an empty window of the requested width.
    pub fn new(window_size: usize) -> Self {
        Self {
            data: vec![[0u8; 32]; window_size],
            heights: vec![0u64; window_size],
            data_len: 0,
            write_cursor: 0,
            last_height: 0,
        }
    }

    /// Append `(hash, height)` to the window. Overwrites the oldest slot once
    /// the window is full. Mirrors the Solidity `appendLayer` semantics.
    pub fn append(&mut self, hash: [u8; 32], height: u64) {
        let w = self.data.len();
        self.data[self.write_cursor] = hash;
        self.heights[self.write_cursor] = height;
        self.write_cursor = (self.write_cursor + 1) % w;
        if self.data_len < w {
            self.data_len += 1;
        }
        self.last_height = height;
    }

    /// Width `W` of this window.
    pub fn window_size(&self) -> usize {
        self.data.len()
    }

    /// Most recent hash (the one just appended), if any.
    pub fn latest(&self) -> Option<[u8; 32]> {
        if self.data_len == 0 {
            return None;
        }
        let w = self.data.len();
        let last_idx = (self.write_cursor + w - 1) % w;
        Some(self.data[last_idx])
    }

    /// Yield slots in chronological order (oldest first → newest last).
    /// Only valid entries are returned; length equals `data_len`.
    pub fn iter_chronological(&self) -> impl Iterator<Item = ([u8; 32], u64)> + '_ {
        let w = self.data.len();
        let len = self.data_len;
        let start = if len < w { 0 } else { self.write_cursor };
        (0..len).map(move |i| {
            let slot = (start + i) % w;
            (self.data[slot], self.heights[slot])
        })
    }

    /// Lookup the slot for a given block height (linear scan; O(W)).
    /// Returns the chronological position [0..data_len) if found.
    pub fn slot_for_height(&self, height: u64) -> Option<usize> {
        self.iter_chronological()
            .position(|(_, h)| h == height)
    }
}

/// Shared bridge state — full mirror of the contract's `GlobalHistoryData`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BridgeState {
    /// `W` — width of every per-layer window. Once set, immutable for the run.
    pub window_size: usize,
    /// Per-layer rolling windows. Index 0 == layer 1.
    pub layer_windows: Vec<HistoryWindow>,
    /// BK set Poseidon commitment (from the node, not self-computed).
    pub stored_bk_set_commitment: [u8; 32],
    /// Highest seq_no whose history was applied via `append_bundle`.
    pub stored_last_seen_block_seq_no: u64,
    /// Block height of that same key block.
    pub stored_last_seen_block_height: u64,
    /// True once the first key block has been applied.
    pub initialized: bool,
    /// Schema version (bumped from v1's flat `Vec<LayerHashEntry>` shape).
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Ring of the most recent `RECENT_BUNDLES_CAP` self-verification outcomes
    /// (oldest at front, newest at back). Written by `bridge-prover-daemon`
    /// after each Circuit 1a + Circuit 2 generation cycle. Empty on schema v2
    /// state files thanks to `#[serde(default)]`.
    #[serde(default)]
    pub recent_bundles: VecDeque<BundleResult>,
}

fn default_schema_version() -> u32 { 3 }

impl BridgeState {
    /// Create an uninitialized state with `MAX_LAYERS` zero windows of the
    /// given width.
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            layer_windows: (0..MAX_LAYERS).map(|_| HistoryWindow::new(window_size)).collect(),
            stored_bk_set_commitment: [0u8; 32],
            stored_last_seen_block_seq_no: 0,
            stored_last_seen_block_height: 0,
            initialized: false,
            schema_version: 3,
            recent_bundles: VecDeque::new(),
        }
    }

    /// Push a `BundleResult` onto the recent-bundles ring, evicting the
    /// oldest entry once the cap is exceeded.
    pub fn push_bundle_result(&mut self, r: BundleResult) {
        if self.recent_bundles.len() >= RECENT_BUNDLES_CAP {
            self.recent_bundles.pop_front();
        }
        self.recent_bundles.push_back(r);
    }

    /// Borrow the window for layer `L` (1-indexed).
    pub fn window(&self, layer: u8) -> &HistoryWindow {
        debug_assert!((1..=MAX_LAYERS as u8).contains(&layer));
        &self.layer_windows[(layer - 1) as usize]
    }

    /// Mutably borrow the window for layer `L` (1-indexed).
    pub fn window_mut(&mut self, layer: u8) -> &mut HistoryWindow {
        debug_assert!((1..=MAX_LAYERS as u8).contains(&layer));
        &mut self.layer_windows[(layer - 1) as usize]
    }

    /// Append one (hash, height) pair to a single layer. Used by tests and
    /// fine-grained callers; production code should usually use
    /// `append_bundle`.
    pub fn append_layer(&mut self, layer: u8, hash: [u8; 32], height: u64) {
        self.window_mut(layer).append(hash, height);
    }

    /// Apply the per-layer hashes extracted from a single key block.
    ///
    /// * `per_layer` — pairs of `(root_hash, layer_number)` from the block's
    ///   `history_proofs` map. Order does not matter; each layer is appended
    ///   into its own window.
    /// * `block_height` / `block_seq_no` — coordinates of the key block that
    ///   produced these hashes.
    /// * `bk_set_commitment` — Poseidon commitment of the current BK set.
    ///
    /// All layers receive the same `block_height` in their `heights[]` slot.
    pub fn append_bundle(
        &mut self,
        per_layer: &[([u8; 32], u8)],
        block_height: u64,
        block_seq_no: u64,
        bk_set_commitment: [u8; 32],
    ) {
        for (hash, layer) in per_layer {
            if (1..=MAX_LAYERS as u8).contains(layer) {
                self.window_mut(*layer).append(*hash, block_height);
            }
        }
        self.stored_bk_set_commitment = bk_set_commitment;
        self.stored_last_seen_block_seq_no = block_seq_no;
        self.stored_last_seen_block_height = block_height;
        self.initialized = true;
    }

    /// Number of layers that have at least one entry. Used by Circuit 2.
    pub fn num_active_layers(&self) -> usize {
        self.layer_windows.iter().filter(|w| w.data_len > 0).count()
    }

    /// Highest layer index (1-based) that has ever been populated.
    /// Returns 0 when no layer has any data. Equivalent to the old
    /// `max_layers_ever_seen` field; in this design once a window receives an
    /// append it stays non-empty, so this is a monotone quantity.
    pub fn max_layers_ever_seen(&self) -> usize {
        self.layer_windows
            .iter()
            .rposition(|w| w.data_len > 0)
            .map(|i| i + 1)
            .unwrap_or(0)
    }

    /// Flatten all layer windows chronologically into a single
    /// `MAX_LAYERS × W` vector. Empty slots are zero. Used to build Circuit 4
    /// public inputs (the `NUM_LAYER_HASHES` candidate list).
    pub fn flatten_layer_hashes(&self) -> Vec<[u8; 32]> {
        let mut out = Vec::with_capacity(MAX_LAYERS * self.window_size);
        for win in &self.layer_windows {
            // Walk in chronological order, then pad to W with zeros.
            let mut count = 0;
            for (hash, _h) in win.iter_chronological() {
                out.push(hash);
                count += 1;
            }
            for _ in count..self.window_size {
                out.push([0u8; 32]);
            }
        }
        out
    }

    /// Given an event observed at `event_height` and layer `L`, return the
    /// chronological slot index within layer L whose `heights[slot]` matches.
    /// Returns `None` if not found (slot rolled out of the window).
    pub fn slot_for_event_height(&self, layer: u8, event_height: u64) -> Option<usize> {
        self.window(layer).slot_for_height(event_height)
    }

    /// Latest hash in the highest occupied layer (the "topmost" window).
    /// Returned only for the *highest* layer that has any data.
    pub fn highest_layer_latest_hash(&self) -> Option<[u8; 32]> {
        for win in self.layer_windows.iter().rev() {
            if win.data_len > 0 {
                return win.latest();
            }
        }
        None
    }

    /// Pick `prev_max_level_layer_hash` for Circuit 2 given that the new key
    /// block carries `new_num_layers` non-empty layers.
    ///
    /// Matches the previous semantics:
    ///   * if `new_num_layers >= t`: latest of the highest currently-active layer
    ///   * if `new_num_layers <  t`: latest of layer `new_num_layers`
    /// where `t = num_active_layers()`.
    pub fn prev_max_level_layer_hash_for(&self, new_num_layers: usize) -> [u8; 32] {
        let t = self.num_active_layers();
        if t == 0 {
            return [0u8; 32];
        }
        let pick = if new_num_layers >= t { t } else { new_num_layers };
        if pick == 0 {
            return [0u8; 32];
        }
        // pick is 1-indexed.
        self.window(pick as u8).latest().unwrap_or([0u8; 32])
    }

    /// Load state from a JSON file (returns new state if file doesn't exist).
    /// `window_size` is used only when the file does not exist.
    pub fn load(path: &str, window_size: usize) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::new(window_size));
        }
        let data = std::fs::read_to_string(path).context("failed to read state file")?;
        let st: BridgeState = serde_json::from_str(&data).context("failed to parse state file")?;
        if st.window_size != window_size {
            anyhow::bail!(
                "state file has window_size={} but daemon configured for W={}; \
                 delete the state file or rebuild with matching W",
                st.window_size,
                window_size
            );
        }
        Ok(st)
    }

    /// Save state to a JSON file atomically.
    ///
    /// Writes to `path.tmp` first, then `rename`s into place. POSIX `rename`
    /// is atomic on the same filesystem, so any concurrent reader sees either
    /// the previous fully-written file or the new fully-written file — never
    /// a half-written one. This is what lets the client daemon `load()` the
    /// state file directly without any locking or IPC handshake.
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self)?;
        let tmp = format!("{}.tmp", path);
        std::fs::write(&tmp, json).with_context(|| format!("failed to write {}", tmp))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("failed to rename {} -> {}", tmp, path))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_append_wraps() {
        let mut w = HistoryWindow::new(4);
        for i in 1..=6u64 {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            w.append(h, i);
        }
        // After 6 appends into a width-4 window: data_len=4, last_height=6,
        // chronological order = heights 3,4,5,6.
        assert_eq!(w.data_len, 4);
        assert_eq!(w.last_height, 6);
        let chron: Vec<u64> = w.iter_chronological().map(|(_, h)| h).collect();
        assert_eq!(chron, vec![3, 4, 5, 6]);
    }

    #[test]
    fn flatten_pads_with_zeros() {
        let mut s = BridgeState::new(4);
        s.append_layer(1, [1u8; 32], 8);
        s.append_layer(1, [2u8; 32], 16);
        s.append_layer(2, [9u8; 32], 64);
        let flat = s.flatten_layer_hashes();
        assert_eq!(flat.len(), MAX_LAYERS * 4);
        assert_eq!(flat[0], [1u8; 32]);
        assert_eq!(flat[1], [2u8; 32]);
        assert_eq!(flat[2], [0u8; 32]);
        assert_eq!(flat[3], [0u8; 32]);
        assert_eq!(flat[4], [9u8; 32]); // layer 2 slot 0
    }

    #[test]
    fn slot_for_event_height_lookup() {
        let mut s = BridgeState::new(8);
        s.append_layer(1, [1u8; 32], 8);
        s.append_layer(1, [2u8; 32], 16);
        s.append_layer(1, [3u8; 32], 24);
        assert_eq!(s.slot_for_event_height(1, 16), Some(1));
        assert_eq!(s.slot_for_event_height(1, 99), None);
    }

    #[test]
    fn prev_max_level_layer_hash_for_matches_old_semantics() {
        let mut s = BridgeState::new(4);
        s.append_layer(1, [1u8; 32], 8);
        s.append_layer(2, [2u8; 32], 16);
        // t = 2 (layers 1 and 2 active)
        // new_num_layers >= 2  ->  latest of layer 2
        assert_eq!(s.prev_max_level_layer_hash_for(3), [2u8; 32]);
        assert_eq!(s.prev_max_level_layer_hash_for(2), [2u8; 32]);
        // new_num_layers == 1  ->  latest of layer 1
        assert_eq!(s.prev_max_level_layer_hash_for(1), [1u8; 32]);
        // new_num_layers == 0  ->  zero
        assert_eq!(s.prev_max_level_layer_hash_for(0), [0u8; 32]);
    }
}
