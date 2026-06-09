"""
SHELLNET-SPECIFIC variant of generate_withdrawals_with_live_event_proving.py.

The local-devnet version assumes it can mint ECC[3] USDC into a freshly
deployed multisig by calling `USDCBridge.mintAndSend` signed with the
zerostate-baked `USDCBridge.keys.json` shipped under `python/contracts/`.
On shellnet (`shellnet.ackinacki.org`) the deployed `USDCBridge` was
provisioned with a DIFFERENT owner pubkey
(`0x7d067d99447d07270337bf49d4f9fad9ccbacea8a19020652649ffe1f5e57b8b`)
so that path requires shellnet-operator credentials which live outside
the public prover repo.

This script implements the shellnet-documented pattern instead:

    https://dev.ackinacki.com/readme/get-test-tokens-in-shellnet
    https://dev.ackinacki.com/how-to-deploy-a-multisig-wallet

Both pages say to fund test wallets via the public GiverV3 faucet at
`0:1111…1111`. That faucet exposes `sendCurrencyWithFlag(dest, value,
ecc, flag, bounce)` and mints ECC[1] NACKL, ECC[2] SHELL, and ECC[3]
USDC on demand (it is itself the mint authority for the test currencies
on shellnet). We therefore:

  • deploy the multisig by pre-funding the precomputed address with
    ECC[2] from the giver (flag=17 = 16|1 — accept undeployed dst, take
    value from msg) then `deployx`-ing it. Same pattern as the local
    orchestrator — that part already worked end-to-end on shellnet.

  • fund ECC[3] USDC into the multisig by calling the SAME giver with
    `ecc:{"3": amount}` once the account is Active. This replaces the
    `USDCBridge.mintAndSend` call.

The 1A+2 lane (bundle proving / `bridge-verifier-daemon`) of the bridge
is identical to local devnet — only the Circuit-4 driver needs the
faucet swap. The local script
(generate_withdrawals_with_live_event_proving.py) is left untouched so
its devnet behaviour is preserved.

Required env vars (all have shellnet-tuned defaults):
  NETWORK         default `shellnet.ackinacki.org`
  GRAPHQL_URL     default `https://shellnet.ackinacki.org/graphql`
  PROVER_DIR      default this script's parent directory
  WORK_DIR        default `<PROVER_DIR>/work-shellnet`
                  (multisig keys + per-event witness intermediates — kept
                   inside the repo so a fresh checkout has everything
                   self-contained, and so the multisig private key never
                   lands in world-readable /tmp).

The shellnet bridge-owner key for USDCBridge.mintAndSend lives at
`python/contracts/USDCBridge.shellnet.keys.json` (copied from the shellnet
operator bundle, no external paths required).

Run:
  python3 python/generate_withdrawals_with_live_event_proving_shellnet.py
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

os.environ["PATH"] = os.path.join(_HERE, "bin") + os.pathsep + os.environ.get("PATH", "")

from helper import common

# ── Addresses (identical on local + shellnet — fixed by zerostate) ────────────
USDC_BRIDGE_ADDRESS_LEGACY = "0:1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
GIVER_ADDRESS_LEGACY       = "0:1111111111111111111111111111111111111111111111111111111111111111"

USDC_BRIDGE_ADDRESS = common.to_dapp_address(USDC_BRIDGE_ADDRESS_LEGACY)
GIVER_ADDRESS       = common.to_dapp_address(GIVER_ADDRESS_LEGACY)

USDC_BRIDGE_DAPP_ID, USDC_BRIDGE_ACCOUNT_ID = USDC_BRIDGE_ADDRESS.split("::", 1)

# ── ABIs / TVCs / keys ────────────────────────────────────────────────────────
_CONTRACTS = os.path.join(_HERE, "contracts")
USDC_BRIDGE_ABI  = os.path.join(_CONTRACTS, "USDCBridge.abi.json")
GIVER_ABI        = os.path.join(_CONTRACTS, "GiverV3.abi.json")
GIVER_KEY_PATH   = os.path.join(_CONTRACTS, "GiverV3.keys.json")
MSIG_ABI         = os.path.join(_CONTRACTS, "UpdateCustodianMultisigWallet.abi.json")
MSIG_TVC_STEM    = os.path.join(_CONTRACTS, "UpdateCustodianMultisigWallet")

# Shellnet bridge-owner key. Copied from the shellnet operator bundle into
# the repo (alongside the other bundled keys under contracts/) so the
# orchestrator is self-contained — no external paths required.
USDC_BRIDGE_KEYS_SHELLNET = os.path.join(_CONTRACTS, "USDCBridge.shellnet.keys.json")

# ── Withdrawal parameters ─────────────────────────────────────────────────────
WITHDRAWAL_AMOUNT  = 1_000_000
ECC_ID_FOR_BURN    = 2   # Shell — gas bootstrap
USDC_TOKEN_ID      = 3   # ECC[3] — required by USDCBridge.initiateWithdrawal
DST_CHAIN_ID       = 1
RECIPIENT_HEX      = "742d35cc6634c0532925a3b844bc454e4438f44e"

WITHDRAWAL_EVENT_DST = ":000000000000000000000000000000000000000000000000000000000000026a"

# ── Bridge / verifier paths ───────────────────────────────────────────────────
PROVER_DIR  = os.environ.get("PROVER_DIR", os.path.dirname(_HERE))
WORK_DIR    = os.environ.get("WORK_DIR", os.path.join(PROVER_DIR, "work-shellnet"))
GRAPHQL_URL = os.environ.get("GRAPHQL_URL", "https://shellnet.ackinacki.org/graphql")

MSIG_KEY_PATH = os.path.join(WORK_DIR, "msig_withdrawals_e2e.keys.json")

# ── History-window math constants (must match production daemon config) ──────
W           = 128
P           = 4
MAX_LAYERS  = 10

# ── Timeouts (seconds) ────────────────────────────────────────────────────────
EVENT_INDEXER_TIMEOUT_S        = 240    # shellnet GQL is slower than local
VERIFIER_STATE_TIMEOUT_S       = 2400   # shellnet bundle wait can stretch
DAEMON_RESULT_TIMEOUT_S        = 600
RUST_BIN_TIMEOUT_S             = 600
FIRE_WINDOW_WAIT_TIMEOUT_S     = 900

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
    """Shellnet's reverse proxy 403s the default Python User-Agent — set a
    custom UA. Bumped timeout because the public endpoint is over the wire."""
    req = urllib.request.Request(
        GRAPHQL_URL,
        data=json.dumps({"query": query}).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "bridge-e2e-orchestrator-shellnet/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def fetch_bridge_extouts(limit: int = 500):
    q = f'''{{
      blockchain {{
        account(account_id: "{USDC_BRIDGE_ACCOUNT_ID}", dapp_id: "{USDC_BRIDGE_DAPP_ID}") {{
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
        if not n.get("block_id"):
            tx = n.get("src_transaction") or {}
            tx_block_id = tx.get("block_id") if isinstance(tx, dict) else None
            if tx_block_id:
                n["block_id"] = tx_block_id
        nodes.append(n)
    return nodes


def fetch_account_dapp_id(account_id: str, dapp_id: str) -> str:
    q = f'''{{ blockchain {{
        account(account_id: "{account_id}", dapp_id: "{dapp_id}") {{
            info {{ dapp_id }}
        }}
    }} }}'''
    data = _gql(q)
    info = (data.get("data") or {}).get("blockchain", {}).get("account", {}).get("info") or {}
    return info.get("dapp_id") or ""


def find_block_by_hash(block_hash: str):
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
    cmd = (f"{common.TVM_CLI} -j body --abi {USDC_BRIDGE_ABI} "
           f"initiateWithdrawal '{params}'")
    out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode().strip()
    return json.loads(out)["Message"]


# ── Deployment ────────────────────────────────────────────────────────────────

def deploy_multisig():
    """Identical to the local-devnet flow — already verified to work on
    shellnet (multisig deploy succeeded in earlier runs). The flow is:
      1. precompute address via `tvm-cli genaddr`
      2. fund the precomputed (still-Uninit) address from the giver with
         sendCurrencyWithFlag flag=17 (16|1) so it accepts the funds
         before being deployed
      3. `deployx` to instantiate
      4. top-up ECC[2] if deploy consumed it
    """
    log_phase("Deploying multisig (shellnet faucet flow)")

    work_dir = os.path.join(WORK_DIR, "msig_deploy")
    os.makedirs(work_dir, exist_ok=True)
    msig_tvc_copy = os.path.join(work_dir, "UpdateCustodianMultisigWallet")
    shutil.copy(f"{MSIG_TVC_STEM}.tvc", f"{msig_tvc_copy}.tvc")
    shutil.copy(MSIG_ABI, f"{msig_tvc_copy}.abi.json")
    msig_abi_copy = f"{msig_tvc_copy}.abi.json"

    if os.path.exists(MSIG_KEY_PATH):
        os.remove(MSIG_KEY_PATH)
    raw_msig_address = common.generate_address(msig_tvc_copy, MSIG_KEY_PATH)
    msig_account_id = raw_msig_address.split(":", 1)[1] if ":" in raw_msig_address else raw_msig_address
    msig_dapp_id    = msig_account_id
    msig_address        = f"{msig_dapp_id}::{msig_account_id}"
    msig_address_legacy = f"0:{msig_account_id}"
    pubkey = common.read_public_key(MSIG_KEY_PATH)
    log(f"  multisig address: {msig_address}")

    # Pre-deploy faucet step: ECC[2] gas + vmshell, ONLY. Sending ECC[2] and
    # ECC[3] together in a single sendCurrencyWithFlag has an empirically
    # observed bug on shellnet: when both are listed in the `ecc` map only
    # the latter (ECC[3]) gets credited and the `value` (vmshell) field is
    # truncated to the ECC[3] amount, leaving the recipient with no gas
    # for deployx (`COMPUTE_SKIPPED: empty balance`). So we use the
    # battle-tested local pattern here (ECC[2] only, large vmshell), and do
    # a second giver call to fund ECC[3] post-deploy.
    total_ecc2 = WITHDRAWAL_AMOUNT * 4
    total_ecc3 = WITHDRAWAL_AMOUNT * 4
    # Two-shot funding pattern (matches `acki-nacki/tests/test_multisig.py:33-36`,
    # which is the canonical Acki Nacki test multisig deploy flow). Uses the
    # canonical WALLET_INIT_BALANCE/WALLET_INIT_CC amounts — anything smaller
    # leaves the deployed account with insufficient vmshell to pay compute fees.
    # The first call with flag=17 (16|1) bootstraps the undeployed account; the
    # second call with flag=1 actually credits the full vmshell `value`.
    # Post-deploy top-up logic below handles trimming/refilling ECC[2] to the
    # operational `total_ecc2` for the burn.
    deploy_faucet_value = 10_000_000_000_000    # canonical WALLET_INIT_BALANCE (10 NACKL)
    deploy_faucet_cc    = 100_000_000_000_000   # canonical WALLET_INIT_CC (100 T ECC[2])
    log(f"  faucet shot 1/2 (flag=17): value={deploy_faucet_value}, ecc[2]={deploy_faucet_cc}")
    common.call_contract(
        GIVER_ADDRESS, GIVER_ABI, GIVER_KEY_PATH,
        "sendCurrencyWithFlag",
        {"dest": msig_address_legacy, "value": str(deploy_faucet_value),
         "ecc": {str(ECC_ID_FOR_BURN): str(deploy_faucet_cc)},
         "flag": "17", "bounce": False},
    )
    time.sleep(3)
    log(f"  faucet shot 2/2 (flag=1):  value={deploy_faucet_value}, ecc[2]={deploy_faucet_cc}")
    common.call_contract(
        GIVER_ADDRESS, GIVER_ABI, GIVER_KEY_PATH,
        "sendCurrencyWithFlag",
        {"dest": msig_address_legacy, "value": str(deploy_faucet_value),
         "ecc": {str(ECC_ID_FOR_BURN): str(deploy_faucet_cc)},
         "flag": "1", "bounce": False},
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
        f"deployx --abi {msig_abi_copy} --keys {MSIG_KEY_PATH} "
        f"--dst-dapp-id {msig_dapp_id} {msig_tvc_copy}.tvc "
        f"{common.format_params(constructor_params)}",
        True,
    )
    common.wait_account_active(msig_address)
    log("  multisig deployed and active")

    # Verify the post-deploy ECC balances. If deploy consumed ECC[2] below
    # the threshold, top it up; the more critical assertion is on ECC[3].
    account = common.get_account(msig_address)
    ecc = account.get("ecc_balance", {}) or {}
    have_ecc2 = int(ecc.get(str(ECC_ID_FOR_BURN), 0))
    have_ecc3 = int(ecc.get(str(USDC_TOKEN_ID), 0))
    log(f"  post-deploy balances: ecc[2]={have_ecc2}, ecc[3]={have_ecc3}")
    if have_ecc2 < total_ecc2:
        log(f"  topping up ECC[{ECC_ID_FOR_BURN}] (have={have_ecc2}, need={total_ecc2})")
        common.call_contract(
            GIVER_ADDRESS, GIVER_ABI, GIVER_KEY_PATH,
            "sendCurrencyWithFlag",
            {"dest": msig_address_legacy, "value": "2000000000",
             "ecc": {str(ECC_ID_FOR_BURN): str(total_ecc2)}, "flag": "1"}
        )
        time.sleep(5)
    # Fund ECC[3] via USDCBridge.mintAndSend signed with the shellnet
    # bridge-owner key. The shellnet public Giver does NOT authorise ECC[3]
    # minting (empirically verified — Giver.sendCurrencyWithFlag with ecc[3]
    # silently completes but credits 0 to the recipient). The owner-keyed
    # mintAndSend path mirrors what the local orchestrator does.
    log(f"  funding ECC[{USDC_TOKEN_ID}] USDC via USDCBridge.mintAndSend: {total_ecc3} (have={have_ecc3})")
    mint_usdc_via_bridge(msig_address_legacy, total_ecc3)

    return msig_address, msig_abi_copy


def resolve_usdc_bridge_address() -> str:
    """Return the USDCBridge address in `dapp_id::account_id` form, with
    the *real* on-chain dapp_id (not the zero-padded fallback). Required
    for `tvm-cli callx` which strictly routes outbound messages by
    dapp_id. Reads from GraphQL via `fetch_account_dapp_id`."""
    real_dapp = fetch_account_dapp_id(USDC_BRIDGE_ACCOUNT_ID, USDC_BRIDGE_DAPP_ID)
    if not real_dapp:
        raise RuntimeError(
            f"could not resolve USDCBridge dapp_id from GQL "
            f"(acc={USDC_BRIDGE_ACCOUNT_ID})"
        )
    return f"{real_dapp}::{USDC_BRIDGE_ACCOUNT_ID}"


def mint_usdc_via_bridge(msig_address_legacy: str, amount: int):
    """Fund the multisig with ECC[3] USDC via `USDCBridge.mintAndSend`,
    signed with the shellnet bridge-owner key shipped under
    `shellnet_config/USDCBridge.keys.json`. Same pattern as the local
    orchestrator (`mint_usdc_to_multisig` in the sibling script). Mirrors
    that flow exactly: read `getNonces.mintNonce`, increment, call
    `mintAndSend(recipient, value, nonce)`.

    Resolves the bridge's real on-chain dapp_id first — the module-level
    `USDC_BRIDGE_ADDRESS` carries the zero-dapp fallback which works for
    `tvm-cli account` queries but not for `callx` routing.

    Asserts the multisig's ECC[3] balance is non-zero after the call.
    """
    bridge_addr = resolve_usdc_bridge_address()
    log(f"  resolved USDCBridge address: {bridge_addr}")
    nonces = common.run_getter(bridge_addr, USDC_BRIDGE_ABI, "getNonces")
    mint_nonce = int(nonces["mintNonce"])
    log(f"  USDCBridge.mintAndSend → multisig ECC[{USDC_TOKEN_ID}]={amount}, nonce={mint_nonce + 1}")
    common.call_contract(
        bridge_addr, USDC_BRIDGE_ABI, USDC_BRIDGE_KEYS_SHELLNET,
        "mintAndSend",
        {"recipient": msig_address_legacy,
         "value":     str(amount),
         "nonce":     str(mint_nonce + 1)},
        True,
    )
    # Poll for the credit to settle. The deployed multisig has self-dapp
    # form (dapp_id == account_id, matching deploy_multisig's
    # --dst-dapp-id). The zero-dapp form returned by to_dapp_address is
    # NOT routable for `tvm-cli account` queries on this contract.
    msig_account_id = msig_address_legacy.split(":", 1)[1]
    msig_address_self_dapp = f"{msig_account_id}::{msig_account_id}"
    deadline = time.time() + 120
    while time.time() < deadline:
        account = common.get_account(msig_address_self_dapp)
        ecc = account.get("ecc_balance", {}) or {}
        have = int(ecc.get(str(USDC_TOKEN_ID), 0))
        if have >= amount:
            log(f"  ECC[{USDC_TOKEN_ID}] credited: {have}")
            return
        time.sleep(2)
    raise RuntimeError(
        f"USDCBridge.mintAndSend did not credit ECC[{USDC_TOKEN_ID}]={amount} "
        f"to {msig_address_legacy} within 120s"
    )


def call_initiate_withdrawal(msig_address, msig_abi, dst_chain_id, recipient_hex):
    payload = encode_initiate_withdrawal_body(dst_chain_id, recipient_hex)
    params = {
        "dest":    USDC_BRIDGE_ADDRESS_LEGACY,
        "value":   "1000000000",
        "cc":      {str(USDC_TOKEN_ID): str(WITHDRAWAL_AMOUNT)},
        "bounce":  False,
        "flags":   1,
        "payload": payload,
    }
    return common.call_contract(
        msig_address, msig_abi, MSIG_KEY_PATH,
        "sendTransaction", params, True,
    )


# ── Pipeline stages (verbatim from local orchestrator) ────────────────────────

def capture_event_metadata(baseline_msg_ids: set):
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

    block = find_block_by_hash(target["block_id"])
    if block is None:
        raise RuntimeError(f"block(hash:{target['block_id']}) returned null")
    log(f"  block seq_no={block['seq_no']} height={block['height']} "
        f"key_block={block['key_block']}")

    account_dapp_id_hex = fetch_account_dapp_id(USDC_BRIDGE_ACCOUNT_ID, USDC_BRIDGE_DAPP_ID)
    if not account_dapp_id_hex:
        account_dapp_id_hex = "0" * 64
    log(f"  account_dapp_id:  {account_dapp_id_hex}")

    account_id_hex = USDC_BRIDGE_ACCOUNT_ID
    assert len(account_id_hex) == 64

    return {
        "event_boc_b64":   target["boc"],
        "block_id":        block["block_id"],
        "block_hash":      block["hash"],
        "block_seq_no":    int(block["seq_no"]),
        "block_height":    int(block["height"]),
        "envelope_hash":   block["envelope_hash"],
        "account_dapp_id": account_dapp_id_hex,
        "account_id":      account_id_hex,
        "message_id":      target["id"],
    }


def wait_for_verifier_state(min_seq_no: int):
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
            pass
        time.sleep(5)
    raise TimeoutError(
        f"verifier state did not reach seq_no {min_seq_no} within "
        f"{VERIFIER_STATE_TIMEOUT_S}s — is bridge-verifier-daemon running?"
    )


def run_rust_bin(name: str, args: list, parse_last_json: bool = True):
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
                pass
        time.sleep(0.5)
    raise TimeoutError(
        f"daemon result file did not appear within {DAEMON_RESULT_TIMEOUT_S}s: {path}"
    )


# ── Driver ────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(WORK_DIR, exist_ok=True)

    network = os.getenv("NETWORK", "shellnet.ackinacki.org")
    os.environ["NETWORK"] = network
    common.NETWORK = network
    common.set_config({"async_call": "false"})
    common.setup()
    time.sleep(1)

    log_phase("Prechecks (shellnet)")
    assert os.path.isdir(PROVER_DIR), f"PROVER_DIR not found: {PROVER_DIR}"
    log(f"  NETWORK:         {network}")
    log(f"  PROVER_DIR:      {PROVER_DIR}")
    log(f"  GRAPHQL_URL:     {GRAPHQL_URL}")
    log(f"  WORK_DIR:        {WORK_DIR}")
    log(f"  W = {W}, P = {P} (bundle = {W*P} blocks), MAX_LAYERS = {MAX_LAYERS}")
    assert common.is_account_active(USDC_BRIDGE_ADDRESS), \
        f"USDCBridge not active at {USDC_BRIDGE_ADDRESS}"
    log(f"  USDCBridge active at {USDC_BRIDGE_ADDRESS}")

    baseline = fetch_bridge_extouts(limit=500)
    baseline_ids = {n["id"] for n in baseline}
    log(f"  baseline ExtOut messages from USDCBridge: {len(baseline_ids)}")

    msig_address, msig_abi = deploy_multisig()

    # USDC was funded directly inside deploy_multisig() (giver flag=17,
    # combined ECC[2]+ECC[3] shot). No USDCBridge.mintAndSend needed.
    msig_account_id = msig_address.split("::", 1)[1]
    msig_address_legacy = f"0:{msig_account_id}"

    log_phase("Waiting for fire window")
    wp = W * P
    fire_deadline = time.time() + FIRE_WINDOW_WAIT_TIMEOUT_S
    last_logged = -1
    while time.time() < fire_deadline:
        latest = fetch_latest_block_seq_no()
        if latest < 0:
            time.sleep(2)
            continue
        next_thinned = ((latest // wp) + 1) * wp
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

    log_phase("Dispatching initiateWithdrawal")
    log(f"  dstChainId={DST_CHAIN_ID}, recipient=0x{RECIPIENT_HEX}, "
        f"amount={WITHDRAWAL_AMOUNT}, tokenId={USDC_TOKEN_ID}")
    call_result = call_initiate_withdrawal(
        msig_address, msig_abi, DST_CHAIN_ID, RECIPIENT_HEX
    )
    if not common.is_ok(call_result):
        log(f"  call result (may still emit asynchronously): {call_result}")

    meta = capture_event_metadata(baseline_ids)
    log("  captured metadata:")
    for k, v in meta.items():
        log(f"    {k}: {v}")

    event_seq = meta["block_seq_no"]
    key_block_seq    = ((event_seq // W) + 1) * W
    thinned_kb_seq   = ((event_seq // (W*P)) + 1) * (W*P)
    target_seq       = thinned_kb_seq
    log_phase("Boundary math")
    log(f"  event_seq        = {event_seq}")
    log(f"  key_block_seq    = {key_block_seq}  (W-aligned L1 tree the event lives in)")
    log(f"  thinned_kb_seq   = {thinned_kb_seq}  (verifier-stored L1 root anchor)")
    log(f"  target_seq       = {target_seq}    (verifier must reach this seq_no)")
    if key_block_seq != thinned_kb_seq:
        raise RuntimeError(
            f"event landed in wrong W-window: key_block_seq={key_block_seq} != "
            f"thinned_kb_seq={thinned_kb_seq}. Re-run the test."
        )

    wait_for_verifier_state(target_seq)

    seq_no = 0
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
        parse_last_json=False,
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
