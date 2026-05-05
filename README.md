# Acki Nacki → Ethereum Bridge: Halo2 Prover & Verifier

Off-chain prover and verifier daemons that generate and verify halo2 KZG proofs for Acki Nacki block attestations. Connects to a running Acki Nacki node via GraphQL, fetches BLS-signed attestations from block data, and produces SNARK proofs that could be verified on Ethereum.

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start (Local Node)](#quick-start-local-node)
- [Quick Start (Shellnet)](#quick-start-shellnet)
- [Configuration](#configuration)
- [BK Set Initialization](#bk-set-initialization)
- [Running the Prover](#running-the-prover)
- [Running the Verifier](#running-the-verifier)
- [Running Both Daemons Together](#running-both-daemons-together)
- [Output and Results](#output-and-results)
- [Evaluating Results](#evaluating-results)
- [Integration Tests](#integration-tests)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
┌──────────────────────┐
│  Acki Nacki Node     │
│  (localhost or       │
│   shellnet)          │
│                      │
│  GraphQL API ────────┼──── http://localhost/graphql
│  Block BOC data      │     https://shellnet.ackinacki.org/graphql
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐       proofs/proof_000042.json
│  Prover Daemon       │ ──────────────────────────────►  ┌──────────────────────┐
│                      │                                   │  Verifier Daemon     │
│  • Fetches block BOC │       proofs/result_000042.json   │                      │
│  • Extracts attesta- │ ◄──────────────────────────────── │  • Reads proof files │
│    tion from common  │                                   │  • Verifies proof    │
│    section           │                                   │  • Writes result     │
│  • Generates halo2   │                                   │  • Tracks last_seen  │
│    proof (~100s)     │                                   │  • Prints summary    │
│  • Logs witnesses    │                                   └──────────────────────┘
└──────────────────────┘

Shared:
  params/          ← SRS, VK, PK (cached, ~3.5 GB total)
  bk_set.json      ← BK set pubkeys (generated or manual)
  proofs/          ← proof + result JSON files (IPC)
  logs/            ← witness dumps on failure
```

The prover and verifier communicate via **file-based IPC**: the prover writes `proofs/proof_{seq_no}.json`, the verifier reads it, verifies, and writes `proofs/result_{seq_no}.json`. The prover waits for the result before proceeding to the next block.

---

## Prerequisites

- **Rust toolchain** (nightly recommended, project uses `opt-level = 3` in dev profile)
- **~4 GB disk** for cached proving key + SRS
- **~16 GB RAM** for proof generation
- **Access to an Acki Nacki node** (local docker or shellnet)

### For local node:

- Docker and docker-compose
- The `acki-nacki` repo cloned locally

### For shellnet:

- Internet access to `https://shellnet.ackinacki.org/graphql`

---

## Quick Start (Local Node)

### 1. Start the local node

```bash
cd /path/to/acki-nacki
git checkout poseidon_profile_new
git checkout -b latest_an_to_eth_bridge_test
make run
# Wait ~2 min for docker build + node startup
# Verify: curl http://localhost/graphql -H "Content-Type: application/json" \
#   -d '{"query":"{ blockchain { blocks(last: 1) { edges { node { seq_no } } } } }"}'
```

### 2. Initialize BK set

For a local node (5 fixed validators), extract BLS pubkeys from node logs:

```bash
docker logs local_gossip_nodes-node0-1 2>&1 | grep "bk_set" | head -5
```

The `bk_set.json` for the standard 5-node local setup is already included in this repo. If your node has different keys, update it manually.

**Format** (`bk_set.json`):
```json
{
  "0": "8380856144f83edc...48-or-96-byte-hex-compressed-pubkey...",
  "1": "871b12c91e4a0917...",
  "2": "a17820823c7ae92a...",
  "3": "94b3dd712b886...",
  "4": "ad2347252db55192..."
}
```

Keys are `signer_index` (string) → `compressed_bls_pubkey_hex` (48 bytes for compressed, 96 for uncompressed).

### 3. Build and run the 10-block test

```bash
cd /path/to/acki-nacki-to-eth-bridge-halo2-prover

# Build all crates
cargo build

# Run the 10-block integration test (takes ~20 min first run, ~17 min cached)
cargo test -p bridge-prover-lib --test live_10_blocks_test -- --nocapture

# First run: generates SRS + VK + PK (~130s), then 10 proofs (~100s each)
# Subsequent runs: loads cached keys (~3s), then 10 proofs
```

---

## Quick Start (Shellnet)

### 1. Extract BK set from shellnet

The BK set can be automatically extracted from shellnet's GraphQL bkSetUpdates:

```bash
# Test extraction
cargo test -p bridge-prover-lib --test shellnet_bk_set_test -- --nocapture
```

Or generate `bk_set.json` programmatically (not yet a CLI command — use the test or write a small script).

**Note:** Shellnet uses **96-byte uncompressed** BLS pubkeys (vs 48-byte compressed on local node). The prover handles both formats.

### 2. Configure and run

Edit the constants in `bridge-prover-daemon/src/main.rs`:

```rust
const GQL_ENDPOINT: &str = "https://shellnet.ackinacki.org/graphql";
```

Then build and run the prover daemon.

---

## Configuration

All configuration is currently via constants in the source code. Key settings:

### Prover Daemon (`bridge-prover-daemon/src/main.rs`)

| Constant | Default | Description |
|----------|---------|-------------|
| `MAX_BLOCKS_TO_PROCESS` | 100 | Stop after this many blocks |
| `SLEEP_BETWEEN_BLOCKS` | 10s | Delay between processing blocks |
| `SLEEP_ON_RETRY` | 5s | Delay when attestation not yet available |
| `INITIAL_WAIT` | 30s | Wait for node to produce blocks at startup |
| `VERIFIER_TIMEOUT` | 60s | Max wait for verifier result file |
| `GQL_ENDPOINT` | `http://localhost/graphql` | Node GraphQL endpoint |
| `PARAMS_DIR` | `./params` | Directory for SRS, VK, PK cache |
| `BK_SET_CONFIG` | `./bk_set.json` | BK set pubkeys file |

### Verifier Daemon (`bridge-verifier-daemon/src/main.rs`)

| Constant | Default | Description |
|----------|---------|-------------|
| `PARAMS_DIR` | `./params` | Must match prover's params dir |
| `POLL_INTERVAL` | 500ms | How often to check for new proof files |
| `MAX_IDLE_WAIT` | 600s | Shutdown after 10 min of no new proofs |

### Circuit Parameters (hardcoded in `bridge-prover-lib/src/keys.rs`)

| Parameter | Value | Description |
|-----------|-------|-------------|
| `K` | 20 | Circuit size (2^20 rows) |
| `LOOKUP_BITS` | 19 | Lookup table size |
| `LIMB_BITS` | 104 | CRT limb bit width |
| `NUM_LIMBS` | 5 | CRT limbs per field element |
| `MAX_SIGNERS` | 300 | Max BK set size (single-VK support) |

---

## BK Set Initialization

The Block Keeper (BK) set contains the BLS public keys of all active validators. The prover needs this to:
1. Compute the Poseidon commitment (public instance)
2. Build the BLS verification circuit

### Option A: Manual config file

Create `bk_set.json` with signer indices and hex-encoded BLS pubkeys:

```json
{
  "0": "8380856144f83edc14392675819248f7da38a53335b44348e6ad390365c3f2566f3206a5d0aab97135f37dba9cb6e491",
  "1": "871b12c91e4a091707d7d503cad6386a8ca564a50e4595f2d5e0f79e604df77c428246dfed9a8c7f8947653597533b25"
}
```

**For local node:** Extract from docker logs (see Quick Start above). The included `bk_set.json` works for the standard 5-node setup.

**For shellnet:** Run the BK set extraction test, then manually save the output to `bk_set.json`.

### Option B: Automatic extraction from GraphQL

The prover daemon attempts to fetch the BK set from GraphQL `bkSetUpdates` first. It queries the history of BK set changes (adds/removes) and reconstructs the current active set.

This works for **shellnet** (where BK set changes are recorded as bkSetUpdates). It may **not work for local nodes** where the BK set is fixed from genesis and no bkSetUpdates exist.

**Fallback:** If GraphQL extraction fails, the prover falls back to `bk_set.json`.

### Pubkey formats

| Source | Format | Size |
|--------|--------|------|
| Local node (docker logs) | Compressed BLS G1 | 48 bytes |
| Shellnet (bkSetUpdates) | Uncompressed BLS G1 | 96 bytes |
| `bk_set.json` | Either format | 48 or 96 bytes |

The circuit's `deserialize_g1_pubkey` handles both formats automatically.

---

## Running the Prover

```bash
# From the project root:
cargo run --bin bridge-prover

# With debug logging:
RUST_LOG=debug cargo run --bin bridge-prover
```

### What happens on first run:

1. Connects to GraphQL endpoint
2. Loads BK set (GraphQL → fallback to `bk_set.json`)
3. Computes Poseidon commitment
4. Generates SRS (`params/kzg_bn254_20.srs`, ~128 MB, ~1s)
5. **Keygen** (`params/primary_vk.bin` + `params/primary_pk.bin`, ~130s) ← only first time
6. Waits 30s for node to produce blocks
7. Enters main loop: fetch attestation → generate proof → write to `proofs/`

### What happens on subsequent runs:

Steps 1-4 same, step 5 loads from cache (~3s), then main loop.

### Output files:

- `proofs/proof_{seq_no:06}.json` — proof + public instances for each block
- `logs/block_{seq_no:06}_witnesses.json` — private witness dump on proof generation failure

---

## Running the Verifier

```bash
# From the project root (same directory as prover):
cargo run --bin bridge-verifier

# With debug logging:
RUST_LOG=debug cargo run --bin bridge-verifier
```

### Prerequisites:

- `bk_set.json` must exist (verifier computes its own Poseidon commitment)
- `params/primary_vk.bin` + `params/primary_config_params.json` must exist (run prover first to generate)
- The verifier does **NOT** need `primary_pk.bin` (saves ~3.5 GB for verifier-only deployments)

### What it does:

1. Loads BK set and computes Poseidon commitment
2. Loads VK + SRS from `params/`
3. Watches `proofs/` directory for new `proof_{seq_no}.json` files
4. For each proof:
   - Validates `last_seen_block_seqno` matches its tracked state
   - Reconstructs the 4 public instances
   - Verifies the halo2 proof (~5ms)
   - Writes `proofs/result_{seq_no:06}.json`
5. After 10 minutes of no new proofs, prints summary and exits

---

## Running Both Daemons Together

Open two terminals in the project root:

```bash
# Terminal 1: Start verifier first (it waits for proofs)
RUST_LOG=info cargo run --bin bridge-verifier

# Terminal 2: Start prover
RUST_LOG=info cargo run --bin bridge-prover
```

The prover generates proofs and writes them to `proofs/`. The verifier picks them up, verifies, and writes results. The prover waits for each result before proceeding.

### Cleanup between runs:

```bash
# Remove old proof/result files to start fresh
rm -rf proofs/*.json

# Optionally remove cached keys to force re-keygen
rm -f params/primary_*.bin params/primary_*.json
```

---

## Output and Results

### Proof files (`proofs/proof_{seq_no:06}.json`)

```json
{
  "block_seq_no": 42,
  "last_seen_block_seqno": 41,
  "envelope_hash_hex": "aabb...64hex...",
  "proof_hex": "ccdd...hex-encoded-8192-byte-proof..."
}
```

### Result files (`proofs/result_{seq_no:06}.json`)

```json
{
  "block_seq_no": 42,
  "verified": true,
  "error": null
}
```

On failure:
```json
{
  "block_seq_no": 42,
  "verified": false,
  "error": "proof verification failed"
}
```

### Witness logs (`logs/block_{seq_no:06}_witnesses.json`)

Written by the prover on proof generation failure:
```json
{
  "block_seq_no": 42,
  "attestation_bytes_hex": "...",
  "bk_set": { "0": "aabb...", "1": "ccdd..." },
  "last_seen_block_seqno": 41
}
```

### Prover summary (stdout at exit)

```
=== PROVER SUMMARY ===
total time:              1840.1s
blocks processed:        10
primary attestations:    10
fallback attestations:   0
skipped blocks:          0
verification OK:         10
verification FAILED:     0
avg proof time:          183.6s
```

### Verifier summary (stdout at exit)

```
=== VERIFIER SUMMARY ===
total time:            1845.3s
total proofs received: 10
verified OK:           10
verified FAILED:       0
```

---

## Evaluating Results

### Key metrics

| Metric | Expected (local, K=20) | Notes |
|--------|----------------------|-------|
| Proof generation time | 85-200s | Varies with CPU load; ~100s solo |
| Verification time | 3-12ms | Very fast |
| Proof size | 8,192 bytes | Constant for K=20, 26 columns |
| Keygen time (first run) | ~130s | Cached after first run |
| SRS load time | ~100ms | Cached to `params/kzg_bn254_20.srs` |

### What to check

1. **All blocks verified OK** — no `VERIFY-FAIL` in results
2. **BK set commitment is constant** across all proofs (same BK set)
3. **block_seq_no is monotonically increasing** — each proof covers the next block
4. **last_seen matches** between prover and verifier — no state desync
5. **No witness logs** in `logs/` — means no proof generation failures

### Investigating failures

If a block fails verification:

1. Check `proofs/result_{seq_no}.json` for the error message
2. Check `logs/block_{seq_no}_witnesses.json` for the private witnesses
3. Common issues:
   - **BK set mismatch**: prover and verifier using different `bk_set.json`
   - **Attestation format**: block BOC structure changed between node versions
   - **Threshold not met**: block has fewer signers than `ceil(2*n/3)`

---

## Integration Tests

All tests require a running node (local or shellnet).

```bash
# BLS verification on a live attestation (fast, ~1s)
cargo test -p bridge-prover-lib --test live_attestation_test -- --nocapture

# Generate and verify 1 proof from live data (~2-4 min)
cargo test -p bridge-prover-lib --test live_proof_test -- --nocapture

# Generate and verify 10 consecutive proofs (~20 min)
cargo test -p bridge-prover-lib --test live_10_blocks_test -- --nocapture

# Extract BK set from shellnet (no local node needed, ~1s)
cargo test -p bridge-prover-lib --test shellnet_bk_set_test -- --nocapture

# BOC parser unit test (no node needed)
cargo test -p bridge-prover-lib -- test_parse_known_attestation --nocapture
```

---

## Project Structure

```
acki-nacki-to-eth-bridge-halo2-prover/
├── Cargo.toml                          # Workspace definition
├── README.md                           # This file
├── bk_set.json                         # BK set pubkeys (local node default)
├── bridge-prover-lib/                  # Core library
│   ├── src/
│   │   ├── lib.rs                      # Re-exports
│   │   ├── gql_client.rs              # GraphQL client (blocks, BOC, bkSetUpdates)
│   │   ├── boc_parser.rs             # Extract attestations from block BOC
│   │   ├── attestation_fetcher.rs     # High-level: fetch attestation + BK set
│   │   ├── poseidon.rs               # Native Poseidon BK set commitment
│   │   ├── keys.rs                    # SRS/VK/PK generation and caching
│   │   ├── prover.rs                 # Proof generation wrapper
│   │   ├── verifier.rs               # Proof verification wrapper
│   │   └── ipc.rs                    # File-based IPC (proof/result JSON)
│   └── tests/
│       ├── live_attestation_test.rs   # BLS verification on live data
│       ├── live_proof_test.rs         # Single proof generation
│       ├── live_10_blocks_test.rs     # 10-block endurance test
│       └── shellnet_bk_set_test.rs    # BK set extraction from shellnet
├── bridge-prover-daemon/               # Prover binary
│   └── src/main.rs                    # Main loop: fetch → prove → write
├── bridge-verifier-daemon/             # Verifier binary
│   └── src/main.rs                    # Watch → verify → write result
├── params/                             # Cached cryptographic artifacts (gitignored)
│   ├── kzg_bn254_20.srs              # SRS (128 MB)
│   ├── primary_vk.bin                # Verification key (3.4 KB)
│   ├── primary_pk.bin                # Proving key (3.5 GB)
│   └── primary_config_params.json    # Circuit parameters
├── proofs/                             # IPC directory (gitignored)
│   ├── proof_000001.json
│   ├── result_000001.json
│   └── ...
└── logs/                               # Failure logs (gitignored)
    └── block_000042_witnesses.json
```

---

## Troubleshooting

### "bk_set.json not found"

The prover/verifier needs the BK set file. For local node, it's included. For shellnet, generate it by running the `shellnet_bk_set_test` and saving the output, or create it manually.

### "primary VK not found"

Run the prover first to generate keys. The verifier needs `params/primary_vk.bin` and `params/primary_config_params.json` (but NOT `primary_pk.bin`).

### "attestation not found for block seq_no=X"

The node may not have produced that block yet, or the block's BOC isn't available via GraphQL. The prover retries with a delay.

### "proof generation failed"

Check `logs/block_*_witnesses.json` for the full witness dump. Common causes:
- Attestation binary format mismatch (node version differs from parser expectations)
- BK set pubkeys don't match what the attestation was signed with
- Block has fewer signers than the primary threshold requires

### Slow proof generation (>200s)

Normal if other CPU-intensive tasks are running. Solo performance is ~100s per proof. The node itself consumes significant CPU.

### "keygen takes too long"

First-run keygen takes ~130s and produces a ~3.5 GB proving key. Subsequent runs load from cache in ~3s. Do not interrupt keygen.
