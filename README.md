# Acki Nacki → Ethereum Bridge: Halo2 Prover & Verifier

Off-chain prover and verifier daemons that produce halo2 KZG proofs covering
**both** sides of the Acki Nacki → Ethereum bridge attestation:

1. **Circuit 1a — Primary Attestation (BLS).** Verifies that ≥ ⌈2n/3⌉ validators
   from the current BK set signed a block attestation, and binds the resulting
   8-leaf SHA-256 Merkle root (the Acki Nacki `block_id`) to the BK-set
   Poseidon commitment.
2. **Circuit 2 — Layer Hashes Movement.** Verifies that the current key
   block's layer hashes Poseidon preimage hashes to the leaf used in
   Circuit 1a (`L0`), and that the highest active layer hash chains
   back to the previously committed `prev_max_level_layer_hash` through a
   sequence of real Poseidon Merkle proof steps.

Together they prove: *"this BK set signed a block whose block_id matches a
block whose history is consistent with everything we have attested to before."*

The daemons connect to a running Acki Nacki node via GraphQL, deserialize the
`boc` field as `Envelope<AckiNackiBlock>` (no node-side modifications needed),
reconstruct real Poseidon trees from intermediate key blocks, and produce SNARK
proofs that can be verified by a counterpart on Ethereum.

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Running Both Daemons Together](#running-both-daemons-together)
- [Output and Results](#output-and-results)
- [Performance](#performance)
- [Evaluating Results](#evaluating-results)
- [Integration Tests](#integration-tests)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
┌──────────────────────┐
│  Acki Nacki Node     │
│  (local Docker)      │
│                      │
│  GraphQL ────────────┼──── http://localhost/graphql
│  • blocks(seq_no)    │     • boc (bincode Envelope<AckiNackiBlock>)
│  • bkSetUpdates      │     • adds / removes (full history)
└──────────┬───────────┘
           │
           ▼
┌─────────────────────────┐                                ┌───────────────────────────┐
│  Prover Daemon          │   proofs/proof_{seqno}.json    │  Verifier Daemon          │
│                         │ ─────────────────────────────► │                           │
│  Per key block (every   │                                │  • Reads proof file       │
│  HISTORY_WINDOW_SIZE    │   proofs/result_{seqno}.json   │  • Recomputes BK Poseidon │
│  blocks):               │ ◄───────────────────────────── │    commitment             │
│                         │                                │  • Verifies Circuit 1a    │
│  1. Fetch block boc     │                                │  • Verifies Circuit 2     │
│  2. Build attestation   │                                │  • Writes result          │
│     witness             │                                │  • Tracks last_seen       │
│  3. Reconstruct real    │                                │  • Updates layer hashes   │
│     Poseidon trees from │                                │    on success             │
│     intermediate blocks │                                └───────────────────────────┘
│  4. Generate Circuit 1a │
│     proof  (~95 s)      │
│  5. Generate Circuit 2  │
│     proof  (~30 s)      │
│  6. Write proof JSON    │
│  7. Wait for result     │
│  8. Persist new layer   │
│     hashes to state     │
└─────────────────────────┘

Shared artifacts on disk:
  params/   — SRS + VK + PK for both circuits (~6.5 GB total, cached)
  state/    — prover_state.json, verifier_state.json (last_key_block_seqno,
              max_layers_ever_seen, persisted layer_hashes per layer)
  proofs/   — proof_{seqno}.json + result_{seqno}.json (file-based IPC)
  logs/     — daemon stdout/stderr (optional)
```

The two daemons communicate via **file-based IPC** in `proofs/`. The prover
writes `proofs/proof_{seqno:06}.json`, the verifier picks it up, verifies both
circuits, and writes `proofs/result_{seqno:06}.json`. The prover blocks on the
result before advancing to the next key block.

**Memory management.** Each PK is large (Circuit 1a ≈ 3.5 GB at K=20,
Circuit 2 ≈ 2.7 GB at K=17). The prover loads them on demand and unloads
after each proof, so peak RSS stays around the larger of the two.

---

## Prerequisites

- **Rust** nightly (the workspace uses `--cfg tokio_unstable` via
  `.cargo/config.toml` and `opt-level = 3` in dev profile)
- **~10 GB free disk** (SRS 128 MB + Circuit 1a PK 3.5 GB + Circuit 2 PK 2.7 GB
  + state/proofs/logs)
- **~16 GB RAM** while a proof is being generated
- **Docker / docker-compose** for the local Acki Nacki node
- The companion repo [`acki-nacki`](https://github.com/gosh-sh/acki-nacki)
  cloned locally, on branch **`latest_an_to_eth_bridge_test`** with
  `HISTORY_PROOF_WINDOW_SIZE = 4`

> The prover deserializes `boc` using the `node` and `node-types` crates from
> branch `latest_an_to_eth_bridge_test`. **No GraphQL schema extensions are
> required** — only the standard `boc` field.

---

## Quick Start

### 1. Start the local Acki Nacki node

```bash
cd /path/to/acki-nacki
git checkout latest_an_to_eth_bridge_test
make run
# Wait ~2 minutes for docker compose build + node startup.

# Sanity-check the GraphQL endpoint:
curl -s http://localhost/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ blockchain { blocks(last: 1) { edges { node { seq_no } } } } }"}'
```

Make sure `node/src/types/history_proof.rs` has
`pub const HISTORY_PROOF_WINDOW_SIZE: usize = 4;` — this **must** match the
prover's `HISTORY_WINDOW_SIZE`.

### 2. Clean state for a fresh test run

```bash
cd /path/to/acki-nacki-to-eth-bridge-halo2-prover
rm -rf proofs/*.json state/*.json logs/*.log
mkdir -p proofs state logs
```

### 3. (First run only) Pre-generate keys

The first run of either daemon will trigger key generation for both circuits.
You can pre-generate them up front by simply launching the prover first — it
runs keygen for both circuits before entering its main loop:

```bash
cargo run --release --bin bridge-prover    # Ctrl-C after keygen if you want
```

This produces under `params/`:

| File | Size | Notes |
|------|------|-------|
| `kzg_bn254_20.srs` | 128 MB | Shared SRS, K=20 (also reused for K=17) |
| `primary_vk.bin` / `primary_pk.bin` | 3.4 KB / 3.5 GB | Circuit 1a |
| `primary_config_params.json` | 181 B | Circuit 1a `BaseCircuitParams` |
| `layer_vk.bin` / `layer_pk.bin` | 2.6 KB / 2.7 GB | Circuit 2 |
| `layer_config_params.json` | 181 B | Circuit 2 `BaseCircuitParams` |

Subsequent runs load from this cache (~3 s per PK).

### 4. Run the verifier and prover together

Open two terminals from the project root.

```bash
# Terminal 1 — Verifier (start it first; it polls proofs/ for new files)
RUST_LOG=info cargo run --release --bin bridge-verifier 2>&1 | tee logs/verifier_output.log
```

```bash
# Terminal 2 — Prover
RUST_LOG=info cargo run --release --bin bridge-prover 2>&1 | tee logs/prover_output.log
```

The prover waits for the node to reach `seq_no >= HISTORY_WINDOW_SIZE` (the
first key block at height 4 with `WINDOW_SIZE=4`), bootstraps the BK set from
GraphQL `bkSetUpdates`, then for each subsequent key block produces a
`proof_{seqno:06}.json`. The verifier picks each one up, verifies both
circuits, and writes `result_{seqno:06}.json`.

Each daemon writes a summary block to stdout when it stops.

### 5. (Optional) Re-run from clean state

```bash
rm -f proofs/*.json state/*.json   # start fresh
# keep params/  if you want to skip keygen, otherwise rm those too
```

---

## Configuration

All configuration is currently via constants in source code.

### Prover (`bridge-prover-daemon/src/main.rs`)

| Constant | Default | Meaning |
|----------|---------|---------|
| `GQL_ENDPOINT` | `http://localhost/graphql` | Acki Nacki GraphQL URL |
| `HISTORY_WINDOW_SIZE` | `4` | **Must match node's `HISTORY_PROOF_WINDOW_SIZE`** |
| `MAX_KEY_BLOCKS_TO_PROCESS` | `20` | Stop after this many key blocks |
| `POLL_INTERVAL` | 3 s | GQL polling interval while waiting for a new key block |
| `SLEEP_ON_RETRY` | 5 s | Backoff when block data is not yet available |
| `VERIFIER_TIMEOUT` | 300 s | Max wait for a `result_{seqno}.json` file |
| `PARAMS_DIR` | `./params` | Cached SRS / VK / PK |
| `LOGS_DIR` | `./logs` | Failure witness dumps |
| `STATE_FILE` | `./state/prover_state.json` | Persisted bridge state |
| `BK_SET_CONFIG` | `./bk_set.json` | Optional fallback if GQL `bkSetUpdates` is empty |

### Verifier (`bridge-verifier-daemon/src/main.rs`)

| Constant | Default | Meaning |
|----------|---------|---------|
| `GQL_ENDPOINT` | `http://localhost/graphql` | For BK set extraction |
| `PARAMS_DIR` | `./params` | Must match prover |
| `POLL_INTERVAL` | 500 ms | How often to scan `proofs/` for new files |
| `MAX_IDLE_WAIT` | 600 s | Auto-shutdown after this idle time |
| `STATE_FILE` | `./state/verifier_state.json` | Independent verifier state |
| `BK_SET_CONFIG` | `./bk_set.json` | Optional fallback |

### Circuit parameters (`bridge-prover-lib/src/keys.rs`)

| Circuit | K | LOOKUP_BITS | Other |
|---------|---|-------------|-------|
| **1a — Primary Attestation** | 20 | 19 | `LIMB_BITS=104`, `NUM_LIMBS=5`, `MAX_SIGNERS=300` |
| **2 — Layer Hashes Movement** | 17 | 16 | `MAX_LAYERS=10`, `MAX_CHAIN_LEN=11`, dense tree depth = 3 |

The dense Poseidon tree has `2 + WINDOW_SIZE = 6` real leaves padded to 8
(depth 3). With `WINDOW_SIZE=4`, layer 1 covers every 4 blocks, layer 2 every
16 blocks, layer 3 every 64 blocks. This is why a clean test reaches layer 3
at key block height 64.

### `tokio_unstable`

`.cargo/config.toml` enables `--cfg tokio_unstable` so the transitively-pulled
`telemetry_utils` from the `node` crate can compile. Don't remove this file.

---

## Running Both Daemons Together

A typical end-to-end test produces ~20 key blocks, all verified OK:

```
$ ls proofs/
proof_000008.json   result_000008.json
proof_000012.json   result_000012.json
proof_000016.json   result_000016.json   ← num_layers transitions 1 → 2
...
proof_000064.json   result_000064.json   ← num_layers transitions 2 → 3
...
proof_000084.json   result_000084.json
```

Each `result` file should report `primary_verified: true, layer_verified: true`.
The verifier auto-shuts-down after `MAX_IDLE_WAIT` of inactivity.

### Cleanup between runs

```bash
# Light reset — keep keys, redo proofs:
rm -f proofs/*.json state/*.json

# Full reset — also force keygen:
rm -f proofs/*.json state/*.json params/primary_*.bin params/layer_*.bin \
      params/primary_config_params.json params/layer_config_params.json
```

---

## Output and Results

### Proof files (`proofs/proof_{seqno:06}.json`)

```json
{
  "block_seq_no": 16,
  "last_seen_block_seqno": 12,
  "block_id_hex": "138105…",
  "primary_proof_hex": "74aedc…",
  "layer_proof_hex":   "…",
  "layer_block_id_hex": "555962…",
  "bk_set_poseidon_hash_hex": "…",
  "num_layers": 2,
  "layer_hash_frs_hex": ["…", "…", "0", "0", "0", "0", "0", "0", "0", "0"],
  "prev_max_level_layer_hash_hex": "…"
}
```

- `primary_proof_hex` — Circuit 1a proof (8,192 bytes).
- `layer_proof_hex` — Circuit 2 proof (6,112 bytes).
- `num_layers` — number of active history layers in the preimage.
- `layer_hash_frs_hex` — `MAX_LAYERS=10` field-element layer roots (the inactive
  trailing slots are zero).

### Result files (`proofs/result_{seqno:06}.json`)

```json
{
  "block_seq_no": 16,
  "primary_verified": true,
  "layer_verified": true,
  "error": null
}
```

On failure `error` is set to e.g. `"primary=true, layer=false"`.

### State files (`state/prover_state.json`, `state/verifier_state.json`)

```json
{
  "layer_hashes": [
    { "layer_number": 1, "root_hash": [...32 bytes...], "from_block_seqno": 84 },
    { "layer_number": 2, "root_hash": [...], "from_block_seqno": 80 },
    { "layer_number": 3, "root_hash": [...], "from_block_seqno": 64 }
  ],
  "last_key_block_seqno": 84,
  "max_layers_ever_seen": 3
}
```

Higher layers are *retained* even when a later key block reports fewer
`history_proofs` entries — this is what lets the chain proof keep moving
through the highest active layer once it has appeared.

### Daemon summaries (stdout at exit)

Prover:

```
=== PROVER SUMMARY ===
total time:              ~2700 s for 20 key blocks
key blocks processed:    20
primary proofs OK:       20
layer proofs OK:         20
verification OK:         20
verification FAILED:     0
avg proof time:          ~130 s
```

Verifier:

```
=== VERIFIER SUMMARY ===
total time:              ~2700 s
total proofs received:   20
both verified OK:        20
primary only OK:         0
layer only OK:           0
both failed:             0
```

---

## Performance

Measured on a local clean run of `latest_an_to_eth_bridge_test`
(`HISTORY_PROOF_WINDOW_SIZE=4`, `MAX_KEY_BLOCKS_TO_PROCESS=20`,
release profile, dev box, blocks 8–84).

### Per-block cost

| Stage | Median | Notes |
|-------|--------|-------|
| Circuit 1a — Primary Attestation proof gen (K=20) | **~95 s** | 24 advice cols, MAX_SIGNERS=300 |
| Circuit 1a verify | **~5 ms** | constant-time |
| Circuit 2 — Layer Hashes Movement proof gen (K=17) | **~30 s** | depth-3 dense tree, MAX_CHAIN_LEN=11 |
| Circuit 2 verify | **~3 ms** | constant-time |
| End-to-end **per key block** (prove both + IPC + verify both) | **~130 s** | Including PK load/unload between circuits |

### Proof artifact sizes

| Artifact | Size |
|----------|------|
| Circuit 1a proof (raw) | 8,192 B |
| Circuit 2 proof (raw) | 6,112 B |
| Combined `proof_{seqno}.json` | ~29 KB |
| `result_{seqno}.json` | ~120 B |

### Cached cryptographic artifacts

| File | Size | Generated in |
|------|------|--------------|
| `params/kzg_bn254_20.srs` | 128 MB | ~1 s (first run) |
| `params/primary_vk.bin` | 3.4 KB | ~37 s |
| `params/primary_pk.bin` | 3.5 GB | ~26 s on top of VK |
| `params/layer_vk.bin` | 2.6 KB | ~10 s |
| `params/layer_pk.bin` | 2.7 GB | ~15 s on top of VK |

Total first-run keygen: ~90 s combined. Subsequent runs load each PK in
~3 s when needed.

### Memory profile

| Phase | Peak RSS |
|-------|----------|
| Idle (no PK loaded) | < 1 GB |
| Circuit 1a proof gen (primary PK loaded) | ~14 GB |
| Circuit 2 proof gen (layer PK loaded) | ~10 GB |

The on-demand PK load/unload in `bridge-prover-daemon/src/main.rs` keeps the
two PKs from being resident simultaneously — without it, peak RSS would be
≥ 22 GB and OOM on most dev machines.

### End-to-end run

Processing 20 consecutive key blocks at `WINDOW_SIZE=4` (heights
8, 12, …, 84) covers every chain scenario:

- **L1 same-layer** (steps 1..3) for blocks 8 → 12, 12 → 16, …
- **L1 → L2 transition** at block 16 (`num_layers` 1 → 2)
- **L2 same-layer** for blocks 16 → 20 → 24 → 28
- **L2 → L3 transition** at block 64 (`num_layers` 2 → 3)
- **L3 same-layer** for blocks 64 → 80 → 84
- **`s < t` edge cases** when a key block reports fewer layers than the
  current `max_layers_ever_seen`

In our latest clean test all 20 of these blocks verified
`BOTH VERIFIED OK` end-to-end.

---

## Evaluating Results

### What to check

1. **`primary_verified` and `layer_verified` are both `true`** in every
   `result_{seqno}.json`.
2. **`num_layers` increases at the expected heights** — 1 for blocks 4..15, 2
   for 16..63, 3 starting at 64 (with `WINDOW_SIZE=4`).
3. **`bk_set_poseidon_hash_hex` is constant** across all proofs while the BK
   set is unchanged.
4. **`block_id_hex` (Circuit 1a output) and `layer_block_id_hex` (Circuit 2
   output)** are emitted separately. Both are derived from the same block but
   from different parts of the witness; cross-circuit binding is enforced
   inside the circuits via the shared `bk_set_poseidon_hash`.
5. **Prover and verifier `last_key_block_seqno` stay in lockstep.**

### Investigating failures

- `proofs/result_{seqno}.json` carries the short error string
  (`primary=true, layer=false` etc.).
- `logs/block_{seqno}_witnesses.json` is written if Circuit 1a witness
  construction itself failed (BLS deserialization or BK-set lookup).
- Common causes:
  - **Window size mismatch** between node and prover (`HISTORY_PROOF_WINDOW_SIZE`
    vs `HISTORY_WINDOW_SIZE`) — Circuit 2 will fail at the chain step.
  - **BK set rotation mid-run** — verifier and prover may briefly disagree on
    the Poseidon commitment; restart both daemons.
  - **`primary=true, layer=false`** at the *first* block after a run timeout —
    state was advanced past the key block but proofs/ wasn't cleared.

---

## Integration Tests

All tests below require a running local Acki Nacki node on
`http://localhost/graphql` (branch `latest_an_to_eth_bridge_test`).

```bash
# BLS verification on a live attestation (~1 s, no proof gen)
cargo test -p bridge-prover-lib --test live_attestation_test -- --nocapture

# Single Circuit 1a proof from live data (~2-3 min, K=20)
cargo test -p bridge-prover-lib --test live_proof_test -- --nocapture

# Both circuits on a single live key block (~2.5 min total)
cargo test -p bridge-prover-lib --test both_circuits_test -- --nocapture

# 10 consecutive Circuit 1a proofs (~20 min)
cargo test -p bridge-prover-lib --test live_10_blocks_test -- --nocapture

# Reconstruct real Poseidon trees from live data and cross-check vs node hashes
cargo test -p bridge-prover-lib --test tree_reconstruction_test -- --nocapture

# BK set extraction from shellnet (no local node needed, ~1 s)
cargo test -p bridge-prover-lib --test shellnet_bk_set_test -- --nocapture
```

---

## Project Structure

```
acki-nacki-to-eth-bridge-halo2-prover/
├── Cargo.toml                          # Workspace
├── .cargo/config.toml                  # --cfg tokio_unstable
├── README.md                           # This file
├── bridge-prover-lib/                  # Core library
│   ├── src/
│   │   ├── lib.rs                      # Re-exports
│   │   ├── gql_client.rs               # GraphQL client (blocks, boc, bkSetUpdates)
│   │   ├── boc_parser.rs               # Attestation extraction from boc
│   │   ├── block_data_parser.rs        # `data` field parser (history_proofs, etc.)
│   │   ├── attestation_fetcher.rs      # High-level attestation+BK fetch
│   │   ├── bk_set_fetcher.rs           # BK set bootstrap from bkSetUpdates / fallback
│   │   ├── poseidon.rs                 # Native Poseidon BK-set commitment
│   │   ├── block_id_tree.rs            # 8-leaf SHA-256 block_id Merkle tree
│   │   ├── chain_proof_builder.rs      # Dense Poseidon Merkle tree + chain links
│   │   ├── real_chain_builder.rs       # Reconstructs L1/L2/L3 trees from real blocks
│   │   ├── bridge_state.rs             # Persisted state (layer hashes, last seqno)
│   │   ├── keys.rs                     # SRS + Circuit 1a + Circuit 2 keygen / cache
│   │   ├── prover.rs                   # Circuit 1a proof generation
│   │   ├── verifier.rs                 # Circuit 1a proof verification
│   │   ├── layer_prover.rs             # Circuit 2 proof generation
│   │   ├── layer_verifier.rs           # Circuit 2 proof verification
│   │   └── ipc.rs                      # File-based IPC (combined proof + result JSON)
│   └── tests/
│       ├── live_attestation_test.rs
│       ├── live_proof_test.rs
│       ├── live_10_blocks_test.rs
│       ├── both_circuits_test.rs
│       ├── tree_reconstruction_test.rs
│       └── shellnet_bk_set_test.rs
├── bridge-prover-daemon/
│   └── src/main.rs                     # Per-key-block: prove 1a + 2, IPC, persist state
├── bridge-verifier-daemon/
│   └── src/main.rs                     # Watch proofs/, verify both circuits, persist
├── params/                             # Cached cryptographic artifacts (gitignored)
├── proofs/                             # IPC directory (gitignored)
├── state/                              # Persisted bridge state (gitignored)
└── logs/                               # Daemon stdout/stderr (gitignored)
```

---

## Troubleshooting

### "primary VK not found" on verifier startup

Run the prover at least once first — it generates the VK and config files for
both circuits. The verifier needs `params/{primary,layer}_vk.bin` and
`params/{primary,layer}_config_params.json` but **not** the PKs.

### "BK set is empty after processing bkSetUpdates"

The GraphQL `bkSetUpdates` history adds + removes netted to zero active
signers. This usually means the genesis BK set isn't represented in
`bkSetUpdates`. Provide a fallback `bk_set.json` (the prover and verifier both
fall back to it).

### Window size mismatch

If the node was built with a different `HISTORY_PROOF_WINDOW_SIZE` than the
prover's `HISTORY_WINDOW_SIZE`, Circuit 2 fails at the dense-tree chain check.
Both must be `4`.

### "spawned_tasks_count not found" / similar tokio errors

The workspace requires `--cfg tokio_unstable` (set in `.cargo/config.toml`).
Don't remove that file. If you cargo-clean and the flag is missing, rebuild
will fail to compile `telemetry_utils` brought in by the `node` crate.

### "node crate workspace conflict"

If you accidentally placed the prover repo *inside* a checkout of `acki-nacki`,
Cargo may try to absorb it into that workspace. The prover uses `node` and
`node-types` as **git** dependencies (pinned to
`branch = "latest_an_to_eth_bridge_test"`), not path dependencies — keep the
two repos in separate directories.

### Verifier idle-shutdown during slow runs

`MAX_IDLE_WAIT` defaults to 600 s. Under heavy load (proof gen > 10 min) the
verifier may exit before the next proof appears. Increase `MAX_IDLE_WAIT` or
restart the verifier — the prover will recover on the next key block.

### Slow proof generation (>200 s for Circuit 1a)

Normal under CPU contention with the local Docker node. Solo numbers on the
same machine are ~95 s for Circuit 1a and ~30 s for Circuit 2.

### Keygen interrupted

If keygen for either circuit is interrupted, delete the partial files:

```bash
rm -f params/primary_pk.bin params/primary_vk.bin params/primary_config_params.json
rm -f params/layer_pk.bin   params/layer_vk.bin   params/layer_config_params.json
```

The next run will redo keygen cleanly.
