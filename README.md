# Acki Nacki → Ethereum Bridge: Halo2 Prover & Verifier

Off-chain daemons that produce and locally verify the halo2 KZG proofs the
Ethereum bridge contract consumes. Three circuits are exercised:

| Circuit | K | Role |
|---|---|---|
| 1A — Primary BLS Attestation | 20 | ≥ ⌈2n/3⌉ BLS signers from the current BK set sign a block; binds `block_id` to `bk_set_poseidon`. |
| 2 — Layer Historical Hashes  | 17 | Open the L0 Poseidon preimage in the `block_id` Merkle tree; advance `GlobalHistoryData` layer windows through a dense Poseidon chain (`MAX_CHAIN_LEN = 11`). |
| 4 — Bridge Event Prover      | 19 | Hash a `WithdrawalInitiated` event BOC, bind it to a `Poseidon96` block leaf, climb the dense chain, anchor against the contract's `MAX_LAYERS × W` candidate hashes via a **private** index. |

Theory, security argument, contract sketch, and per-circuit witness details live in the companion repo: [`acki-nacki-to-eth-bridge-halo2-circuits/README.md`](../acki-nacki-to-eth-bridge-halo2-circuits/README.md). This README covers the **off-chain operation**: daemons, IPC, state, and how to run the full E2E test from this checkout.

> **Notation — `W` ≡ `HISTORY_PROOF_WINDOW_SIZE`** (and `P` ≡ `THINNING_FACTOR_P`).

---

## Table of Contents

- [Architecture](#architecture)
- [Repository Layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [E2E Test Runbook](#e2e-test-runbook)
- [Configuration](#configuration)
- [IPC, State, and On-disk Artifacts](#ipc-state-and-on-disk-artifacts)
- [Performance](#performance)
- [Integration Tests](#integration-tests)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
              ┌──────────────────────────┐
              │  Acki Nacki Node         │
              │  (5-node Docker compose) │
              │  http://localhost/graphql│
              └────────────┬─────────────┘
                           │ GQL (blocks, bk-set, history-proofs metadata)
       ┌───────────────────┼────────────────────────────┐
       ▼                                                ▼
┌─────────────────────┐                  ┌────────────────────────────┐
│ bridge-prover       │   proofs/        │ bridge-verifier            │
│  • Circuit 1A       │ ───────────────► │  • Reads proof_*.json      │
│  • Circuit 2        │  proof_NNN.json  │  • Verifies 1A + 2         │
│  • One bundle per   │ ◄─────────────── │  • Advances layerWindows   │
│    thinned KB       │  result_NNN.json │  • Watches proof_event_*   │
│    (W·P blocks)     │                  │  • Verifies Circuit 4      │
└─────────────────────┘                  └────────────────────────────┘
                           ▲                       ▲
                           │ proof_event_NNN.json  │
                           │                       │
┌──────────────────────────┴────────────────┐      │
│ Per WithdrawalInitiated event:            │      │
│   bridge-event-private-witness-export ─►  │      │
│   bridge-event-witness-builder        ─►  │      │
│   bridge-event-prove --fixture ...    ────┘      │
│ (driven by the Python E2E orchestrator)          │
└──────────────────────────────────────────────────┘
```

Both halves of the system are **file-based**: `proofs/proof_NNN.json` is the prover→verifier channel; `proofs/proof_NNN.result.json` (or `result_NNN.json` for block bundles) is the verifier→prover ACK. The verifier daemon's own state (`state/verifier_state.json`) is the off-chain twin of the Ethereum contract's `layerWindows` storage.

**On-demand PK loading.** Each proving key is ~3 GB. The prover loads one circuit's PK, generates a proof, then unloads before loading the next — peak RSS stays around 14 GB instead of 22+.

---

## Repository Layout

```
acki-nacki-to-eth-bridge-halo2-prover/
├── bridge-prover-lib/                     # shared library
│   └── src/{keys,prover,verifier,layer_prover,layer_verifier,
│            event_prover,event_verifier,ipc,bridge_state,…}.rs
├── bridge-prover-daemon/                  # bin "bridge-prover"        (Circuits 1A + 2)
├── bridge-verifier-daemon/                # bin "bridge-verifier"      (all three circuits)
├── bridge-event-prove-daemon/             # bin "bridge-event-prove"   (Circuit 4, one-shot)
├── bridge-event-private-witness-export/   # bin: dump PartialPrivateWitness from a block
├── bridge-event-witness-builder/          # bin: enrich it via GQL + verifier state
├── params/   state/   proofs/   logs/     # gitignored; created on demand
└── .cargo/config.toml                     # --cfg tokio_unstable (required, do not remove)
```

`THINNING_FACTOR_P` is defined in `bridge-prover-lib/src/lib.rs:35`. `HISTORY_WINDOW_SIZE` is **driven** by the `node-block-client` git dependency's `HISTORY_PROOF_WINDOW_SIZE` — see `bridge-prover-daemon/src/main.rs:42`. Node and prover therefore cannot disagree on `W` at the constant level (but the node Docker image still has to be rebuilt after changing it — see Step 1 below).

---

## Prerequisites

- **Rust nightly** (release builds).
- **~10 GB free disk** under `params/` (KZG SRS + three PKs).
- **~16 GB RAM** during proof generation.
- **Docker / docker compose** for the local 5-node Acki Nacki cluster.
- Sibling checkout of [`acki-nacki`](https://github.com/gosh-sh/acki-nacki) with the matching `HISTORY_PROOF_WINDOW_SIZE` (see runbook Step 0).
- Python 3 + `tvm-cli` on PATH for the orchestrator.

---

## E2E Test Runbook

Drives one full bridge cycle: deploy multisig → emit `WithdrawalInitiated` → wait for thinned key block → build private witness → prove Circuit 4 → verifier ACKs.

### Step 0 — Confirm `W` and `P` agree everywhere

| File | Setting |
|---|---|
| `acki-nacki/node/libs/node-block-client/src/history_proof.rs` | `HISTORY_PROOF_WINDOW_SIZE = 128` |
| `acki-nacki/node/src/types/history_proof.rs` | same |
| `bridge-prover-lib/src/lib.rs` | `THINNING_FACTOR_P = 4` |
| `Cargo.toml` | `bridge-event-prove-circuit features = ["w-128"]` |
| `acki-nacki/tests/exchange/generate_withdrawals_with_live_event_proving.py` | `W = 128, P = 4` |

Changing `W` requires rebuilding the node image **and** re-running Circuit 4 keygen — its VK is `W`-specific. Circuits 1A/2 PKs are `W`-independent.

### Step 1 — Build / refresh the cluster

```bash
cd /path/to/acki-nacki
make run                       # kill + build_node + run_silent
docker ps                       # expect node{0..4}, q_server0, block_manager, nginx0, aerospike
```

First-ever build: 10–20 min. Incremental rebuilds use the Docker cache.

### Step 2 — Wipe stale prover state (keep keys)

```bash
cd /path/to/acki-nacki-to-eth-bridge-halo2-prover
rm -f state/* proofs/proof_*.json proofs/result_*.json \
      proofs/proof_event_*.json proofs/proof_event_*.result.json
# Do NOT delete params/ — KZG SRS + PKs/VKs survive across runs.
```

### Step 3 — Generate proving / verifying keys (first run only)

All commands run from the root of **this** repo. Skip files that already exist.

| Circuit | Files produced under `params/` | Command |
|---|---|---|
| 1A — Primary Attestation (K=20) | `primary_vk.bin`, `primary_pk.bin` (~3.5 GB) | `cargo run --release --bin bridge-prover` (generates 1A then 2 on first start, ~90 s combined, then keeps running). |
| 2 — Layer Historical Hashes (K=17) | `layer_vk.bin`, `layer_pk.bin` (~2.7 GB) | same — produced by the `bridge-prover` run above. |
| 4 — Bridge Event Prover (K=19) | `event_vk.bin`, `event_pk.bin` | `cargo run --release --bin bridge-event-prove -- --selftest` (~5 min). **Must run before** `bridge-verifier` — verifier bails on missing VKs. |

After switching `W` (e.g. `w-8` ↔ `w-128`), delete `params/event_*.bin` and re-run the `--selftest` line.

### Step 4 — Start the daemons

Two terminals (or `run_in_background`):

```bash
# Terminal A — bundle prover (Circuits 1A + 2)
cargo run --release --bin bridge-prover

# Terminal B — verifier (loads all three VKs; watches proofs/)
cargo run --release --bin bridge-verifier
```

The prover bootstraps from the first key block (`seq_no ≥ W`) and writes `state/bootstrap_seed.json`; the verifier reads that seed. **Start the prover first.** The verifier runs indefinitely — send `SIGINT` to stop.

### Step 5 — Run the orchestrator

```bash
cd /path/to/acki-nacki
NETWORK=localhost python3 tests/exchange/generate_withdrawals_with_live_event_proving.py
```

Orchestrator phases (printed with `[T+MM:SS]` timestamps):

1. Deploy multisig wallet, fund with ECC[2].
2. Send `WithdrawalInitiated` via `TokenBridge`.
3. Poll GraphQL for the ExtOut message, recover `(block_seq_no, block_height, envelope_hash, account_dapp_id, account_id)`.
4. Compute `thinned_kb_seq = ((event_seq // (W·P)) + 1) · W · P` and wait for the verifier state to advance to it.
5. Invoke (from this repo): `bridge-event-private-witness-export` → `bridge-event-witness-builder` → `bridge-event-prove --fixture <enriched.json> --out-dir proofs/`.
6. Wait for `proofs/proof_event_NNN.result.json` from the verifier daemon.
7. Assert `verified == true` and `anchor_matched == true`. Exit 0.

### Step 6 — Inspect results

```bash
ls proofs/
# proof_000512.json  result_000512.json
# proof_001024.json  result_001024.json
# proof_event_000000.json  proof_event_000000.result.json

# Per-circuit timings (primary/layer/event proof_gen_ms fields)
python3 -c "
import json, glob
for f in sorted(glob.glob('proofs/proof_*.json')):
    d = json.load(open(f))
    print(f, d.get('primary_proof_gen_ms','-'),'ms primary,',
              d.get('layer_proof_gen_ms','-'),'ms layer,',
              d.get('event_proof_gen_ms','-'),'ms event')
"
```

---

## Configuration

All configuration lives as constants in source (no env vars).

### Prover (`bridge-prover-daemon/src/main.rs`)

| Constant | Default | Meaning |
|---|---|---|
| `GQL_ENDPOINT` | `http://localhost/graphql` | Acki Nacki GraphQL URL |
| `HISTORY_WINDOW_SIZE` | inherited from `node-block-client::HISTORY_PROOF_WINDOW_SIZE` | The shared `W`. |
| `POLL_INTERVAL` | 3 s | Loop sleep while waiting for the next key block |
| `SLEEP_ON_RETRY` | 5 s | Backoff when block data isn't yet available |
| `VERIFIER_TIMEOUT` | 300 s | Max wait for a verifier result file |
| `STATS_LOG_INTERVAL` | 60 s | Period of summary log lines |
| `PARAMS_DIR` / `STATE_FILE` / `LOGS_DIR` / `BK_SET_CONFIG` | `./params` / `./state/prover_state.json` / `./logs` / `./bk_set.json` | On-disk locations |

### Verifier (`bridge-verifier-daemon/src/main.rs`)

| Constant | Default | Meaning |
|---|---|---|
| `GQL_ENDPOINT` | `http://localhost/graphql` | For BK set extraction |
| `HISTORY_WINDOW_SIZE` | shared with the prover via the same crate | – |
| `POLL_INTERVAL` | 500 ms | How often `proofs/` is scanned |
| `STATS_LOG_INTERVAL` | 60 s | – |
| `PARAMS_DIR` / `STATE_FILE` / `BK_SET_CONFIG` | `./params` / `./state/verifier_state.json` / `./bk_set.json` | – |

### Thinning (`bridge-prover-lib/src/lib.rs`)

| Constant | Default | Meaning |
|---|---|---|
| `THINNING_FACTOR_P` | `4` | One bundle every `P` key blocks; bundle covers `W·P` source blocks. |

### `tokio_unstable`

`.cargo/config.toml` sets `--cfg tokio_unstable` because the transitively-pulled `telemetry_utils` from the node crate requires it. Do not delete that file.

---

## IPC, State, and On-disk Artifacts

### `proofs/proof_NNN.json` (block bundles, written by the prover)

```json
{
  "block_seq_no": 512,
  "last_seen_block_seqno": 0,
  "block_id_hex": "…",
  "primary_proof_hex": "…",   "primary_proof_gen_ms": 102392,
  "layer_proof_hex":   "…",   "layer_proof_gen_ms":   137310,
  "layer_block_id_hex": "…",
  "bk_set_poseidon_hash_hex": "…",
  "num_layers": 2,
  "layer_hash_frs_hex": ["…", "…", "0", … (MAX_LAYERS = 10 entries)],
  "prev_max_level_layer_hash_hex": "…"
}
```

### `proofs/proof_event_NNN.json` (Circuit 4, written by `bridge-event-prove`)

```json
{
  "schema_version": 1,
  "seq_no": 0,
  "proof_hex": "…",
  "public_instances_hex": ["…", "…", …],
  "self_verified": true,
  "event_proof_gen_ms": 152166
}
```

### `proofs/result_NNN.json` / `proof_event_NNN.result.json` (verifier ACK)

Result for a block bundle:
```json
{ "block_seq_no": 512, "primary_verified": true, "layer_verified": true, "error": null }
```

Result for an event proof:
```json
{ "verified": true, "anchor_matched": true, "anchor_layer": 1, "anchor_slot": 17 }
```

### `state/prover_state.json` and `state/verifier_state.json`

Persisted bridge state — layer hashes per active layer (1..`max_layers_ever_seen`), the last relayed key-block seqno/height, BK set commitment. The verifier file is the canonical off-chain mirror of the Ethereum contract's `layerWindows` storage.

### `state/bootstrap_seed.json`

Written by the prover on first run from the first key block's envelope; consumed by the verifier on startup so both halves agree on initial `(bk_set, height, last_seen)`.

---

## Performance

Measured on a local dev box (release profile, `opt-level = 3` in dev profile too) against a 5-node devnet at ~3 source blocks/s, `W = 128, P = 4`.

### Per-proof generation (latest E2E run)

| Circuit | K | Range |
|---|---|---|
| 1A (Primary BLS) | 20 | 102 – 144 s |
| 2 (Layer Historical Hashes) | 17 | 103 – 137 s |
| 4 (Bridge Event Prover) | 19 | ~152 s (n=1) |

Verify times: ~5 ms (1A), ~3 ms (2), ~110 ms (4). All constant-time.

### Whole E2E cycle

| Metric | Value |
|---|---|
| Wall-clock (event emit → verifier ACK) | **~11:18** |
| Bundles relayed before Circuit 4 is admissible | 2 (`thinned_kb_seq = 1024`) |
| Bundle width on source side | `W·P = 512` blocks ≈ 4 min on devnet |

### Cached cryptographic artifacts

| File | Size |
|---|---|
| `params/kzg_bn254_*.srs` | total 128 MB at K=20 (K=17/19 reuse) |
| `params/primary_pk.bin` | ~3.5 GB |
| `params/layer_pk.bin` | ~2.7 GB |
| `params/event_pk.bin` | ~3+ GB |

Peak RSS stays around the largest of the three (load-on-demand).

---

## Integration Tests

All require the local Acki Nacki cluster up on `http://localhost/graphql`.

```bash
cargo test -p bridge-prover-lib --test live_attestation_test  -- --nocapture  # BLS verify, no proof gen, ~1 s
cargo test -p bridge-prover-lib --test live_proof_test        -- --nocapture  # Circuit 1A from live, K=20, ~2-3 min
cargo test -p bridge-prover-lib --test both_circuits_test     -- --nocapture  # 1A + 2 on one key block, ~2.5 min
cargo test -p bridge-prover-lib --test live_10_blocks_test    -- --nocapture  # 10× Circuit 1A, ~20 min
cargo test -p bridge-prover-lib --test tree_reconstruction_test -- --nocapture  # rebuild L1/L2/L3 from real blocks
cargo test -p bridge-prover-lib --test shellnet_bk_set_test   -- --nocapture  # BK set extraction (no local node)
cargo test -p bridge-prover-lib --test event_prover           -- --nocapture  # Circuit 4 standalone
```

---

## Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| Verifier exits with `"primary VK not found"` or `"layer VK not found"` | Run `bridge-prover` first — it generates 1A/2 keys on initial start. |
| Verifier exits with `"event VK not found"` | Run `cargo run --release --bin bridge-event-prove -- --selftest` once. |
| Orchestrator hits `VERIFIER_STATE_TIMEOUT_S` | One bundle ≈ 4 min on devnet — confirm the prover is producing bundles (its stdout). |
| `non-monotone height` in verifier log | `state/` was wiped without restarting the cluster (chain is past the persisted `last_seen_block_height`). Restart cluster, or restore `state/bootstrap_seed.json` from backup. |
| W mismatch — verifier rejects bundles with wrong layer count | Node Docker image and prover binary disagree on `HISTORY_PROOF_WINDOW_SIZE`. Re-run `make run` after editing `history_proof.rs`. |
| Circuit 4 verification fails on a fresh `W` | Cached `event_vk.bin` is for the previous `W`. Delete `params/event_*.bin` and re-run keygen. |
| `spawned_tasks_count not found` / similar tokio errors | `--cfg tokio_unstable` missing. Restore `.cargo/config.toml`. |
| `node crate workspace conflict` | Don't place this repo inside `acki-nacki/`. Both `node-block-client` and `node-types` are git dependencies. |
| Keygen interrupted | Delete partial `params/{primary,layer,event}_*.bin` and re-run. |
