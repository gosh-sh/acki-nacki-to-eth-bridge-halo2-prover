"""
End-to-end test of the Acki Nacki → Ethereum bridge Circuit 4
(`WithdrawalInitiated` event) proving pipeline on a live cluster.

Standalone copy: this script and its `helper.common` dependency live entirely
under `python/` in this repository, so a consumer who only has the prover
repo (no acki-nacki checkout) can run it against an already-running node.
Contract ABIs/TVCs and the GiverV3 keypair are bundled under
`python/contracts/`. Original lives at
`acki-nacki/tests/exchange/generate_withdrawals_with_live_event_proving.py`.

Pipeline (single event for v1; loopable later):

  1. Deploy multisig + fund with ECC[2] (same pattern as
     `tests/exchange/generate_withdrawals.py`).
  2. Trigger ONE `WithdrawalInitiated` event via TokenBridge.
  3. Capture event metadata via GraphQL — (event_boc_b64, block_id,
     block_seq_no, block_height, envelope_hash, account_dapp_id,
     account_id) — by:
        a. Polling `account(...).messages(msg_type: [ExtOut])` for the
           emitted message (`dst` = WithdrawalInitiatedEmit external addr).
        b. Reading `Message.block_id` and `Message.src_dapp_id` directly.
        c. Scanning recent `blocks(last: …)` for the matching `block_id`
           to recover `seq_no`, `envelope_hash`, `height`.
  4. Wait for the L1 key-block window summarising the event to be
     ingested by the verifier daemon (`verifier_state.json` advances).
     Target seq_no = `((event_seq // W) + 1) * W + W`  (W = 8 in test
     config; equals `HISTORY_PROOF_WINDOW_SIZE`).
  5. Run `bridge-event-private-witness-export` → `partial.json`.
  6. Run `bridge-event-witness-builder` → `witness.json`.
  7. Run `bridge-event-halo2-prover --fixture witness.json --out-dir <prover>/proofs`
     → writes `proof_event_NNNNNN.json` for the verifier daemon to pick up,
     and self-verifies (informational only — the daemon's verdict is the
     real gate).
  8. Wait for `<prover>/proofs/proof_event_NNNNNN.result.json` to appear
     (written by the daemon's Track D4a watch loop).
  9. Assert `result.verified is True` and `result.anchor_matched is True`.

Prerequisites (the script does not start these — they must be live):
  - Acki Nacki cluster running (default GRAPHQL_URL=http://localhost/graphql).
  - `bridge-verifier-daemon` running in $PROVER_DIR (Track D4a build).
  - $PROVER_DIR/params/ has primary + layer + event VK/PK (the daemon
    will bail at boot if event VK is missing).
  - Release builds present:
        $PROVER_DIR/target/release/bridge-event-private-witness-export
        $PROVER_DIR/target/release/bridge-event-witness-builder
        $PROVER_DIR/target/release/bridge-event-halo2-prover

Env vars (all optional):
  PROVER_DIR   — default: this script's parent directory (the repo root)
  GRAPHQL_URL  — default http://localhost/graphql
  NETWORK      — tvm-cli endpoint URL (default http://127.0.0.1:80)
  WORK_DIR     — default /tmp/bridge-e2e

Run from anywhere — paths are anchored to this script's location:
  # Local devnet:
  python3 python/generate_withdrawals_with_live_event_proving.py
  # Shellnet:
  NETWORK=shellnet.ackinacki.org \
      GRAPHQL_URL=https://shellnet.ackinacki.org/graphql \
      python3 python/generate_withdrawals_with_live_event_proving.py

Exit code:
  0 if the daemon accepted the Circuit 4 proof (verified && anchor_matched).
  non-zero on any pipeline failure; artefacts left under $WORK_DIR for
  forensics.
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

# Bundled `tvm-cli` lives under `python/bin/` — prepend to PATH so
# `helper.common`'s `shutil.which("tvm-cli")` resolves it. Override with
# `CLI_NAME` env var to point at a different binary.
os.environ["PATH"] = os.path.join(_HERE, "bin") + os.pathsep + os.environ.get("PATH", "")

from helper import common

# ── Addresses ─────────────────────────────────────────────────────────────────
TOKEN_BRIDGE_ADDRESS = "0:1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
GIVER_ADDRESS        = "0:1111111111111111111111111111111111111111111111111111111111111111"

# ── ABIs / TVCs (bundled under python/contracts/) ─────────────────────────────
_CONTRACTS = os.path.join(_HERE, "contracts")
TOKEN_BRIDGE_ABI = os.path.join(_CONTRACTS, "TokenBridge.abi.json")
GIVER_ABI        = os.path.join(_CONTRACTS, "GiverV3.abi.json")
GIVER_KEY_PATH   = os.path.join(_CONTRACTS, "GiverV3.keys.json")
MSIG_ABI         = os.path.join(_CONTRACTS, "UpdateCustodianMultisigWallet.abi.json")
MSIG_TVC_STEM    = os.path.join(_CONTRACTS, "UpdateCustodianMultisigWallet")

# ── Withdrawal parameters ─────────────────────────────────────────────────────
# Only one event for v1 — the goal is to validate the pipeline, not throughput.
WITHDRAWAL_AMOUNT  = 1_000_000
ECC_ID_FOR_BURN    = 2   # Shell (giver has it at genesis)
DST_CHAIN_ID       = 1
RECIPIENT_HEX      = "742d35cc6634c0532925a3b844bc454e4438f44e"

# External-address dst for the WithdrawalInitiated event:
#   makeAddrExtern(WithdrawalInitiatedEmit=618=0x26a, bitCntAddress=256)
WITHDRAWAL_EVENT_DST = ":000000000000000000000000000000000000000000000000000000000000026a"

# ── Bridge / verifier paths ───────────────────────────────────────────────────
# Default PROVER_DIR: the repo root (this script lives at <repo>/python/).
PROVER_DIR  = os.environ.get("PROVER_DIR", os.path.dirname(_HERE))
WORK_DIR    = os.environ.get("WORK_DIR", "/tmp/bridge-e2e")
GRAPHQL_URL = os.environ.get("GRAPHQL_URL", "http://localhost/graphql")

# Multisig keypair is generated by the script itself — write it under WORK_DIR
# so the bundled `python/contracts/` stays read-only.
MSIG_KEY_PATH = os.path.join(WORK_DIR, "msig_withdrawals_e2e.keys.json")

# ── History-window math constants ─────────────────────────────────────────────
# W = HISTORY_PROOF_WINDOW_SIZE. Production: 128.
# P = THINNING_FACTOR_P. Prover proves every P-th key block; bundle width = W*P.
# Keep both in sync with `history_proof::HISTORY_PROOF_WINDOW_SIZE`
# (acki-nacki/node/libs/history-proof/src/lib.rs) and
# `bridge-prover-lib::THINNING_FACTOR_P`.
W           = 128
P           = 4
MAX_LAYERS  = 10

# ── Timeouts (seconds) ────────────────────────────────────────────────────────
EVENT_INDEXER_TIMEOUT_S        = 120
VERIFIER_STATE_TIMEOUT_S       = 1800   # W=128, P=4: ~4 bundles × ~4 min = 16 min
DAEMON_RESULT_TIMEOUT_S        = 600    # wait for daemon to verify the event proof
RUST_BIN_TIMEOUT_S             = 600    # event prove at W=128 K=19 (~1-2 min)
FIRE_WINDOW_WAIT_TIMEOUT_S     = 600    # wait for chain to enter the firing window

# ── Tracing ───────────────────────────────────────────────────────────────────
_T0 = time.time()


def t_prefix():
    elapsed = int(time.time() - _T0)
    m, s = divmod(elapsed, 60)
    return f"[T+{m:02d}:{s:02d}]"


def log_phase(msg):
    print(f"\n{t_prefix()} === {msg} ===", flush=True)


def log(msg):
    print(f"{t_prefix()} {msg}", flush=True)


# ── GraphQL helpers ───────────────────────────────────────────────────────────

def _gql(query: str):
    req = urllib.request.Request(
        GRAPHQL_URL,
        data=json.dumps({"query": query}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def fetch_bridge_extouts(limit: int = 500):
    """Fetch recent ExtOut messages from TokenBridge with all fields needed
    for downstream Circuit 4 witness construction in one round-trip."""
    q = f'''{{
      blockchain {{
        account(address: "{TOKEN_BRIDGE_ADDRESS}") {{
          messages(msg_type: [ExtOut], last: {limit}) {{
            edges {{ node {{
              id boc body src dst created_at
              block_id src_dapp_id
              src_transaction {{ id block_id }}
            }} }}
          }}
        }}
      }}
    }}'''
    data = _gql(q)
    edges = (data.get("data") or {}).get("blockchain", {}).get("account", {}) \
        .get("messages", {}).get("edges", []) or []
    nodes = []
    for e in edges:
        n = e["node"]
        # Message.block_id is null on ExtOut in this schema; fall back to the
        # owning transaction's block_id, which is populated.
        if not n.get("block_id"):
            tx = n.get("src_transaction") or {}
            tx_block_id = tx.get("block_id") if isinstance(tx, dict) else None
            if tx_block_id:
                n["block_id"] = tx_block_id
        nodes.append(n)
    return nodes


def fetch_account_dapp_id(address: str) -> str:
    q = f'{{ blockchain {{ account(address: "{address}") {{ info {{ dapp_id }} }} }} }}'
    data = _gql(q)
    info = (data.get("data") or {}).get("blockchain", {}).get("account", {}).get("info") or {}
    return info.get("dapp_id") or ""


def find_block_by_hash(block_hash: str):
    """Resolve a block via direct `block(hash:)` lookup.

    Note: what `Message.src_transaction.block_id` actually returns is the
    block's `hash` field (BOC hash), NOT its consensus `block_id`. The block's
    real `block_id` and `envelope_hash` come from this lookup."""
    q = f'''{{
      blockchain {{
        block(hash: "{block_hash}") {{
          hash block_id seq_no height envelope_hash key_block
        }}
      }}
    }}'''
    data = _gql(q)
    return (data.get("data") or {}).get("blockchain", {}).get("block")


def fetch_latest_block_seq_no() -> int:
    q = '{ blockchain { blocks(last: 1) { edges { node { seq_no } } } } }'
    try:
        data = _gql(q)
        edges = data["data"]["blockchain"]["blocks"]["edges"]
        return int(edges[-1]["node"]["seq_no"])
    except Exception:
        return -1


# ── tvm-cli body encoding ─────────────────────────────────────────────────────

def encode_initiate_withdrawal_body(dst_chain_id: int, recipient_hex: str) -> str:
    params = json.dumps({
        "dstChainId": str(dst_chain_id),
        "recipient":  recipient_hex,
    })
    cmd = (f"{common.TVM_CLI} -j body --abi {TOKEN_BRIDGE_ABI} "
           f"initiateWithdrawal '{params}'")
    out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode().strip()
    return json.loads(out)["Message"]


# ── Deployment ────────────────────────────────────────────────────────────────

def deploy_multisig():
    log_phase("Deploying multisig")

    work_dir = "/tmp/msig_withdrawals_e2e"
    os.makedirs(work_dir, exist_ok=True)
    msig_tvc_copy = os.path.join(work_dir, "UpdateCustodianMultisigWallet")
    shutil.copy(f"{MSIG_TVC_STEM}.tvc", f"{msig_tvc_copy}.tvc")
    shutil.copy(MSIG_ABI, f"{msig_tvc_copy}.abi.json")
    msig_abi_copy = f"{msig_tvc_copy}.abi.json"

    if os.path.exists(MSIG_KEY_PATH):
        os.remove(MSIG_KEY_PATH)
    msig_address = common.generate_address(msig_tvc_copy, MSIG_KEY_PATH)
    pubkey = common.read_public_key(MSIG_KEY_PATH)
    log(f"  multisig address: {msig_address}")

    # Fund via direct giver call (works on local + shellnet — same GIVER_ADDRESS
    # constant, no reliance on `tests/GiverV3.address` which only exists after
    # local `make run`). Pattern mirrors v2_setup.py::deploy_msig_funded:
    # single sendCurrencyWithFlag with flag=17 (16|1) and an ample native value
    # to also bootstrap vmshell on the new account.
    total_ecc = WITHDRAWAL_AMOUNT * 4
    fund_value = max(total_ecc, 100_000_000_000_000)
    log(f"  funding via giver call_contract ecc[{ECC_ID_FOR_BURN}]={fund_value}")
    common.call_contract(
        GIVER_ADDRESS, GIVER_ABI, GIVER_KEY_PATH,
        "sendCurrencyWithFlag",
        {
            "dest":   msig_address,
            "value":  "200000000000000",
            "ecc":    {str(ECC_ID_FOR_BURN): str(fund_value)},
            "flag":   "17",
            "bounce": False,
        },
    )
    time.sleep(8)
    for _ in range(60):
        account = common.get_account(msig_address)
        if 'acc_type' in account:
            log(f"  account appeared: {account['acc_type']} "
                f"ecc={account.get('ecc_balance')}")
            break
        time.sleep(1)

    constructor_params = {
        "owners_pubkey":   [f"0x{pubkey}"],
        "owners_address":  [],
        "reqConfirms":     1,
        "reqConfirmsData": 1,
        "value":           100_000_000,
    }
    common.execute_cli_cmd(
        f"deployx --abi {msig_abi_copy} --keys {MSIG_KEY_PATH} {msig_tvc_copy}.tvc "
        f"{common.format_params(constructor_params)}",
        True,
    )
    common.wait_account_active(msig_address)
    log("  multisig deployed and active")

    # Top up ECC if deploy ate into it
    account = common.get_account(msig_address)
    ecc = account.get("ecc_balance", {}) or {}
    have = int(ecc.get(str(ECC_ID_FOR_BURN), 0))
    if have < total_ecc:
        log(f"  topping up ECC[{ECC_ID_FOR_BURN}] (have={have}, need={total_ecc})")
        common.call_contract(
            GIVER_ADDRESS, GIVER_ABI, GIVER_KEY_PATH,
            "sendCurrencyWithFlag",
            {"dest": msig_address, "value": "2000000000",
             "ecc": {str(ECC_ID_FOR_BURN): str(total_ecc)}, "flag": "1"}
        )
        time.sleep(5)

    return msig_address, msig_abi_copy


def call_initiate_withdrawal(msig_address, msig_abi, dst_chain_id, recipient_hex):
    payload = encode_initiate_withdrawal_body(dst_chain_id, recipient_hex)
    params = {
        "dest":    TOKEN_BRIDGE_ADDRESS,
        "value":   "1000000000",
        "cc":      {str(ECC_ID_FOR_BURN): str(WITHDRAWAL_AMOUNT)},
        "bounce":  False,
        "flags":   1,
        "payload": payload,
    }
    return common.call_contract(
        msig_address, msig_abi, MSIG_KEY_PATH,
        "sendTransaction", params, True,
    )


# ── Pipeline stages ───────────────────────────────────────────────────────────

def capture_event_metadata(baseline_msg_ids: set):
    """Wait for our newly-emitted WithdrawalInitiated event to surface, then
    resolve its block via GQL. Returns the merged metadata dict."""
    log_phase("Waiting for emitted WithdrawalInitiated event")
    deadline = time.time() + EVENT_INDEXER_TIMEOUT_S
    target = None
    last_log = -1
    while time.time() < deadline:
        nodes = fetch_bridge_extouts(limit=500)
        matched = [
            n for n in nodes
            if n.get("dst") == WITHDRAWAL_EVENT_DST
            and n.get("id") not in baseline_msg_ids
        ]
        if len(matched) != last_log:
            log(f"  matched={len(matched)} new event(s)")
            last_log = len(matched)
        if matched:
            # Take the newest
            matched.sort(key=lambda n: n.get("created_at") or 0)
            target = matched[-1]
            break
        time.sleep(2)

    if target is None:
        raise RuntimeError("did not observe a WithdrawalInitiated event within "
                           f"{EVENT_INDEXER_TIMEOUT_S}s")

    log(f"  event message id:    {target['id']}")
    log(f"  src_transaction.block_id (== Block.hash): {target['block_id']}")
    log(f"  src_dapp_id:         {target.get('src_dapp_id')}")

    # `target['block_id']` is actually the block's `hash` field — use it for
    # the direct `block(hash:)` lookup to obtain the real consensus block_id
    # and envelope_hash.
    block = find_block_by_hash(target["block_id"])
    if block is None:
        raise RuntimeError(f"block(hash:{target['block_id']}) returned null")
    log(f"  block seq_no={block['seq_no']} height={block['height']} "
        f"key_block={block['key_block']}")

    # Pull TokenBridge's own dapp_id (separate from Message.src_dapp_id,
    # which on a workchain root account is also expected to be zero).
    account_dapp_id_hex = fetch_account_dapp_id(TOKEN_BRIDGE_ADDRESS)
    if not account_dapp_id_hex:
        # Workchain root has empty dapp_id — pad to 32 zero bytes which is
        # what the exporter's hex parser will accept.
        account_dapp_id_hex = "0" * 64
    log(f"  account_dapp_id:  {account_dapp_id_hex}")

    # account_id = the trailing 32 bytes of TokenBridge address
    # ("0:1a1a1a..." → "1a1a1a...")
    account_id_hex = TOKEN_BRIDGE_ADDRESS.split(":", 1)[1]
    assert len(account_id_hex) == 64

    return {
        "event_boc_b64":   target["boc"],
        "block_id":        block["block_id"],   # consensus block_id from block lookup
        "block_hash":      block["hash"],
        "block_seq_no":    int(block["seq_no"]),
        "block_height":    int(block["height"]),
        "envelope_hash":   block["envelope_hash"],
        "account_dapp_id": account_dapp_id_hex,
        "account_id":      account_id_hex,
        "message_id":      target["id"],
    }


def wait_for_verifier_state(min_seq_no: int):
    """Block until the verifier daemon has ingested at least up to
    `min_seq_no` (i.e. its state file reports
    `stored_last_seen_block_seq_no >= min_seq_no`).
    """
    state_path = os.path.join(PROVER_DIR, "state", "verifier_state.json")
    log_phase(f"Waiting for verifier state to reach seq_no >= {min_seq_no}")
    log(f"  state file: {state_path}")
    deadline = time.time() + VERIFIER_STATE_TIMEOUT_S
    last_log_seq = -1
    while time.time() < deadline:
        try:
            with open(state_path) as f:
                state = json.load(f)
            current = int(state.get("stored_last_seen_block_seq_no", 0))
            if current != last_log_seq:
                latest = fetch_latest_block_seq_no()
                log(f"  verifier at seq_no={current}, chain at seq_no={latest}")
                last_log_seq = current
            if current >= min_seq_no:
                log(f"  verifier reached seq_no={current} (>= {min_seq_no})")
                return current
        except FileNotFoundError:
            log(f"  state file not present yet — daemon may still be starting")
        except json.JSONDecodeError:
            # Mid-write race — try again next tick.
            pass
        time.sleep(5)
    raise TimeoutError(
        f"verifier state did not reach seq_no {min_seq_no} within "
        f"{VERIFIER_STATE_TIMEOUT_S}s — is bridge-verifier-daemon running?"
    )


def run_rust_bin(name: str, args: list, parse_last_json: bool = True):
    """Invoke a release Rust binary, log its progress, return either the
    parsed last-non-empty-line JSON summary (default) or the raw stdout."""
    bin_path = os.path.join(PROVER_DIR, "target", "release", name)
    if not os.path.isfile(bin_path):
        raise FileNotFoundError(
            f"{bin_path} not found — did you `cargo build --release -p {name}` "
            f"in {PROVER_DIR}?"
        )
    cmd = [bin_path] + args
    log(f"  $ {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=RUST_BIN_TIMEOUT_S,
        cwd=PROVER_DIR,
    )
    if proc.returncode != 0:
        # Stderr carries tracing output; stdout would normally have the JSON.
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"{name} exited with code {proc.returncode}")

    if not parse_last_json:
        return proc.stdout

    last_non_empty = next(
        (ln for ln in reversed(proc.stdout.splitlines()) if ln.strip()),
        None,
    )
    if not last_non_empty:
        raise RuntimeError(f"{name} produced no stdout")
    try:
        return json.loads(last_non_empty)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"{name} last stdout line is not valid JSON: {last_non_empty[:200]!r} "
            f"({e})"
        )


def wait_for_daemon_result(seq_no: int):
    """Wait for `proofs/proof_event_NNNNNN.result.json` to appear in
    $PROVER_DIR and parse it."""
    path = os.path.join(PROVER_DIR, "proofs", f"proof_event_{seq_no:06d}.result.json")
    log_phase("Waiting for verifier daemon's result file")
    log(f"  path: {path}")
    deadline = time.time() + DAEMON_RESULT_TIMEOUT_S
    while time.time() < deadline:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return json.load(f)
            except json.JSONDecodeError:
                # Mid-write race; the daemon writes the file in one go but
                # be defensive — retry on next tick.
                pass
        time.sleep(0.5)
    raise TimeoutError(
        f"daemon result file did not appear within {DAEMON_RESULT_TIMEOUT_S}s: {path}"
    )


# ── Driver ────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(WORK_DIR, exist_ok=True)

    # Network configuration: same pattern as tests/dex/shellnet_test.py — set
    # NETWORK both in env and in `common` module global, then call
    # `common.setup()` which runs `tvm-cli config --url $NETWORK`. async_call
    # off so call_contract returns once the message is mined, not just queued
    # (essential for deterministic E2E ordering).
    network = os.getenv("NETWORK", "http://127.0.0.1:80")
    os.environ["NETWORK"] = network
    common.NETWORK = network
    common.set_config({"async_call": "false"})
    common.setup()
    time.sleep(1)

    log_phase("Prechecks")
    assert os.path.isdir(PROVER_DIR), f"PROVER_DIR not found: {PROVER_DIR}"
    log(f"  NETWORK:     {network}")
    log(f"  PROVER_DIR:  {PROVER_DIR}")
    log(f"  GRAPHQL_URL: {GRAPHQL_URL}")
    log(f"  W = {W}, P = {P} (bundle = {W*P} blocks), MAX_LAYERS = {MAX_LAYERS}")
    assert common.is_account_active(TOKEN_BRIDGE_ADDRESS), \
        f"TokenBridge not active at {TOKEN_BRIDGE_ADDRESS}"
    log(f"  TokenBridge active at {TOKEN_BRIDGE_ADDRESS}")

    # Snapshot the ExtOut messages that already exist so we can identify
    # OUR event by exclusion. The cluster may have prior runs in its history.
    baseline = fetch_bridge_extouts(limit=500)
    baseline_ids = {n["id"] for n in baseline}
    log(f"  baseline ExtOut messages from TokenBridge: {len(baseline_ids)}")

    msig_address, msig_abi = deploy_multisig()

    # ─── Wait for the firing window ───────────────────────────────────────
    # With thinning factor P=4, the verifier only stores L1 roots at
    # (W*P)-aligned key blocks. The witness builder requires the event to
    # land in the LAST W-window before the next thinned key block (i.e.
    # event_seq ∈ [K-W, K-1] for some K ≡ 0 mod (W*P)).
    #
    # Wait until the chain enters that firing window, then fire. The
    # transaction's ExtOut typically lands within 1-3 blocks of dispatch,
    # so we aim for `latest_seq` exactly at the start of the last W-window.
    log_phase("Waiting for fire window")
    wp = W * P
    fire_deadline = time.time() + FIRE_WINDOW_WAIT_TIMEOUT_S
    last_logged = -1
    while time.time() < fire_deadline:
        latest = fetch_latest_block_seq_no()
        if latest < 0:
            time.sleep(2)
            continue
        # Next thinned key block strictly after latest:
        next_thinned = ((latest // wp) + 1) * wp
        # Start of its last W-window:
        fire_start = next_thinned - W
        if latest != last_logged:
            log(f"  latest_seq={latest}, next_thinned_kb={next_thinned}, "
                f"fire_start={fire_start}")
            last_logged = latest
        if latest >= fire_start:
            log(f"  ENTERED fire window: latest={latest} ∈ [{fire_start}..{next_thinned})")
            break
        time.sleep(2)
    else:
        raise TimeoutError(
            f"chain never entered fire window within {FIRE_WINDOW_WAIT_TIMEOUT_S}s"
        )

    # ─── Trigger one event ────────────────────────────────────────────────
    log_phase("Dispatching initiateWithdrawal")
    log(f"  dstChainId={DST_CHAIN_ID}, recipient=0x{RECIPIENT_HEX}, "
        f"amount={WITHDRAWAL_AMOUNT}, tokenId={ECC_ID_FOR_BURN}")
    call_result = call_initiate_withdrawal(
        msig_address, msig_abi, DST_CHAIN_ID, RECIPIENT_HEX
    )
    if not common.is_ok(call_result):
        log(f"  call result (may still emit asynchronously): {call_result}")

    # ─── Capture metadata ─────────────────────────────────────────────────
    meta = capture_event_metadata(baseline_ids)
    log("  captured metadata:")
    for k, v in meta.items():
        log(f"    {k}: {v}")

    # ─── Boundary math ────────────────────────────────────────────────────
    # The L1 key block at seq_no `H` summarises blocks [H-W, H-1]. With
    # thinning the verifier persists L1 roots only at (W*P)-aligned key
    # blocks, so we wait until the verifier reaches one full bundle past
    # the bundle containing the event.
    event_seq = meta["block_seq_no"]
    key_block_seq    = ((event_seq // W) + 1) * W           # W-aligned (block_tree_proof root)
    thinned_kb_seq   = ((event_seq // (W*P)) + 1) * (W*P)   # next thinned key block after event
    # The L1 root committed by the Circuit 2 proof at `thinned_kb_seq` IS the
    # Circuit 4 anchor — no need to wait an extra bundle.
    target_seq       = thinned_kb_seq
    log_phase("Boundary math")
    log(f"  event_seq        = {event_seq}")
    log(f"  key_block_seq    = {key_block_seq}  (W-aligned L1 tree the event lives in)")
    log(f"  thinned_kb_seq   = {thinned_kb_seq}  (verifier-stored L1 root anchor)")
    log(f"  target_seq       = {target_seq}    (verifier must reach this seq_no)")
    if key_block_seq != thinned_kb_seq:
        raise RuntimeError(
            f"event landed in wrong W-window: key_block_seq={key_block_seq} != "
            f"thinned_kb_seq={thinned_kb_seq}. The fire-window timing missed; "
            f"chain probably advanced past the boundary before the event landed. "
            f"Re-run the test."
        )

    wait_for_verifier_state(target_seq)

    # ─── Run the three Rust binaries ─────────────────────────────────────
    seq_no = 0  # event-proof seqno space (independent of bundle seqno)
    work_event_dir = os.path.join(WORK_DIR, f"event_{seq_no:06d}")
    os.makedirs(work_event_dir, exist_ok=True)
    partial_path = os.path.join(work_event_dir, "partial.json")
    witness_path = os.path.join(work_event_dir, "witness.json")
    proofs_dir   = os.path.join(PROVER_DIR, "proofs")
    log(f"  work dir:    {work_event_dir}")
    log(f"  proofs dir:  {proofs_dir}")

    log_phase("Step 5: bridge-event-private-witness-export")
    run_rust_bin(
        "bridge-event-private-witness-export",
        [
            "--event-boc-b64",   meta["event_boc_b64"],
            "--block-id",        meta["block_id"],
            "--block-seq-no",    str(meta["block_seq_no"]),
            "--account-dapp-id", meta["account_dapp_id"],
            "--account-id",      meta["account_id"],
            "--envelope-hash",   meta["envelope_hash"],
            "--out",             partial_path,
        ],
        parse_last_json=False,  # this binary writes only a file + tracing
    )
    assert os.path.isfile(partial_path), f"exporter did not produce {partial_path}"
    log(f"  wrote {partial_path}")

    log_phase("Step 6: bridge-event-witness-builder")
    wb_summary = run_rust_bin(
        "bridge-event-witness-builder",
        [
            "--partial-witness", partial_path,
            "--out",             witness_path,
            "--verifier-state",  os.path.join(PROVER_DIR, "state/verifier_state.json"),
            "--gql-endpoint",    GRAPHQL_URL,
            "--layer-idx",       "0",
        ],
    )
    log(f"  summary: {json.dumps(wb_summary, indent=2)}")
    assert os.path.isfile(witness_path), f"witness-builder did not produce {witness_path}"

    log_phase(f"Step 7: bridge-event-halo2-prover (seq_no={seq_no})")
    ep_summary = run_rust_bin(
        "bridge-event-halo2-prover",
        [
            "--fixture",  witness_path,
            "--out-dir",  proofs_dir,
            "--seq-no",   str(seq_no),
        ],
    )
    log(f"  summary: schema={ep_summary.get('schema_version')}, "
        f"self_verified={ep_summary.get('self_verified')}, "
        f"proof_file={ep_summary.get('proof_file')}")
    if not ep_summary.get("self_verified"):
        log("  WARNING: prover-side self-verify FAILED — daemon will reject too")

    # ─── Wait for daemon verdict (V2) ─────────────────────────────────────
    result = wait_for_daemon_result(seq_no)
    log_phase("Daemon verdict")
    log(json.dumps(result, indent=2))

    verified       = result.get("verified") is True
    anchor_matched = result.get("anchor_matched") is True
    if not anchor_matched:
        log(f"  ANCHOR MISMATCH: {result.get('error')}")
    if not verified:
        log(f"  VERIFICATION FAILED: {result.get('error')}")

    if verified and anchor_matched:
        log_phase("END-TO-END SUCCESS")
        log(f"  daemon verified Circuit 4 proof for event in block "
            f"seq_no={event_seq} at verifier height "
            f"{result.get('verified_at_block_height')}")
        log(f"  artefacts: {work_event_dir} + {proofs_dir}/proof_event_{seq_no:06d}.json")
        sys.exit(0)
    else:
        log_phase("END-TO-END FAILURE")
        log(f"  artefacts kept for diagnosis under {work_event_dir}")
        sys.exit(1)


if __name__ == "__main__":
    main()
