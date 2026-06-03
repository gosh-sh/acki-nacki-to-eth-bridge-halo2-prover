# Phase 1 — End-to-End Test Runbook

Structural regression test for the prover↔verifier pair: schema-v2 wire
format, per-layer `HistoryWindow` mirrors, atomic state writes, indefinite
operation, and clean restart-resume.

Proof correctness is covered by the integration tests in
`bridge-prover-lib/tests/`; this runbook is about plumbing.

## Scope

- **Single-thread testbed** (`poseidon_dex` / `test_bridge_poseidon_dex`):
  `block_height == seq_no` by construction. Multi-thread divergence is a
  later phase.
- **W = 8**, pinned via `bridge_prover_lib::poseidon_dense::HISTORY_PROOF_WINDOW_SIZE`.
  First key block at `seq_no = 8`, L1→L2 transition at `seq_no = 64`.
- **README.md is stale** (still references removed `MAX_KEY_BLOCKS_TO_PROCESS`
  / v1 flat state); this file is the current behavior.

## Prerequisites

Local Docker Acki Nacki node on `test_bridge_poseidon_dex` at `seq_no >= 8`.
Confirm:
```bash
curl -s http://localhost/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ blockchain { blocks(last: 1) { edges { node { seq_no } } } } }"}'
```

## Procedure

```bash
# Fresh start (wipes proofs/ state/ logs/, keeps params/).
scripts/run-bridge-test.sh

# Watch progress.
tail -f logs/verifier_output.log logs/prover_output.log
```

Torn-read watchdog in a separate terminal — should print nothing:
```bash
while true; do
  jq -e . state/verifier_state.json >/dev/null 2>&1 || echo "TORN $(date +%T)"
  jq -e . state/prover_state.json   >/dev/null 2>&1 || echo "TORN $(date +%T)"
  sleep 0.05
done
```

Full bar = 5 verified key blocks (seq 8, 16, 24, 32, 40); smoke = 3 (8, 16, 24).
Criterion G (L1→L2) needs seq 64, so 8 verified key blocks.

Stop cleanly:
```bash
scripts/stop-bridge-test.sh
```

For criterion I (restart-resume): re-launch the daemons **without** wiping —
use the `cargo run --release --bin bridge-verifier` / `bridge-prover`
commands directly, since `run-bridge-test.sh` always wipes.

## Pass criteria

Minimum-bar smoke = A–E. Full = A–I.

- **A. Clean startup.** Both banners log; verifier logs `VKs loaded
  (primary + layer)`; no panic backtrace.

- **B. Init reads true block_height from envelope.** Prover log:
  `first key block: <N> history_proofs layers, block_height=<H>` then
  `initialized from seed: seqno=8, height=<H>, layers=<N>`. Verifier log:
  `bootstrapping from seed at ./state/bootstrap_seed.json: seqno=8, ...`.
  On W=8 single-thread, `H == 8`.

- **C. Three consecutive key blocks verified.**
  ```bash
  for seq in 000008 000016 000024; do
    jq -r '"\(.block_seq_no): primary=\(.primary_verified) layer=\(.layer_verified)"' \
      proofs/result_${seq}.json 2>/dev/null || echo "$seq: no result"
  done
  ```
  Expect `primary=true layer=true` for 16 and 24 (block 8 is bootstrap-only,
  no proof file).

- **D. Schema-v2 wire format.**
  ```bash
  for f in proofs/proof_*.json; do
    jq -r '"\(.block_seq_no): schema=\(.schema_version) height=\(.block_height)"' "$f"
  done
  ```
  Every line: `schema=2`, non-zero `height`.

- **E. No torn reads.** Watchdog printed nothing.

- **F. Prover ↔ verifier state parity** after 5+ verified blocks:
  ```bash
  for daemon in prover verifier; do
    jq '{seq: .stored_last_seen_block_seq_no,
         height: .stored_last_seen_block_height,
         bk: .stored_bk_set_commitment,
         layers: (.layer_windows
                  | map({len: .data_len, cur: .write_cursor, h: .last_height}))}' \
      state/${daemon}_state.json
  done
  ```
  Top-level **and** per-layer outputs identical (the bootstrap-seed fix
  guarantees the L1 entry for block 8 is mirrored on both sides).

- **G. L1→L2 transition at seq 64** (needs 8 verified blocks):
  ```bash
  jq '.num_layers, .layer_hash_frs_hex[0:3]'   proofs/proof_000064.json
  jq '.layer_windows[1].data_len'              state/verifier_state.json
  ```
  `num_layers=2`, the second hex is non-zero, verifier's L2 `data_len >= 1`.

- **H. Clean Ctrl-C.** Both exit 0 with a `=== … SUMMARY ===` block.
  `verifier_state.json` parses and reflects the last `result_*.json`.

- **I. Restart resumes correctly.** After a non-wipe restart (manual cargo
  run, not the launcher), prover logs
  `state loaded: initialized=true, last_key_block=<last_seq>` matching the
  pre-shutdown value. Next proof file is at `<last_seq> + W`. Pre-existing
  `proof_*.json` are not overwritten (compare `stat -f "%m %N" proofs/*.json`
  before/after).

## Optional negative test — schema mismatch

```bash
scripts/stop-bridge-test.sh
jq '.schema_version = 1' proofs/proof_000016.json > /tmp/v1.json \
  && mv /tmp/v1.json proofs/proof_000016.json
rm proofs/result_000016.json
RUST_LOG=info cargo run --release --bin bridge-verifier
```
Expect log: `proof file proofs/proof_000016.json has schema_version=1 but
verifier expects 2`. Verifier writes `VerifyResult { error: Some(...) }`
and continues; does not crash.

## Troubleshooting (Phase 1 only)

- **Every proof rejected as `schema_version=… but verifier expects 2`** —
  prover and verifier are from different builds. Rebuild both:
  `cargo build --release --workspace`.

- **State files diverge between daemons (F fails)** — likely a stale state
  file from a previous run with different `W`. Run `scripts/run-bridge-test.sh`
  for a clean start. Cross-check `proof_<N>.json.block_height` against
  `verifier_state.json.stored_last_seen_block_height` for the same `<N>`;
  mismatch means the two daemons saw different envelopes.

- **Torn-read watchdog fires** — `BridgeState::save` / `BootstrapSeed::save`
  write `.tmp` then `rename`. `state/` and `state/.tmp` must be on the same
  filesystem for `rename` to be atomic.

- **Restart skips ahead** — `prover_state.json` was deleted while
  `verifier_state.json` wasn't. The launcher wipes both together; if you
  deleted manually, delete the other one too.
