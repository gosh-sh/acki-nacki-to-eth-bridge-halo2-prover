#!/usr/bin/env bash
# Start prover+verifier on n14 against a local GraphQL cluster via reverse SSH tunnel.
set -euo pipefail

SSH_HOST="${SSH_HOST:-gosh@94.156.178.14}"
SSH_PORT="${SSH_PORT:-22488}"
REMOTE_DIR="${REMOTE_DIR:-/mnt/data/gosh/sergey-bridge/acki-nacki-to-eth-bridge-halo2-prover}"
BOOTSTRAP="${BRIDGE_BOOTSTRAP_SEQNO:-1024}"
LOCAL_GQL_PORT="${LOCAL_GQL_PORT:-80}"
REMOTE_GQL_PORT="${REMOTE_GQL_PORT:-18080}"

echo "==> reverse tunnel remote:${REMOTE_GQL_PORT} -> local:${LOCAL_GQL_PORT}"
if ! pgrep -f "127.0.0.1:${REMOTE_GQL_PORT}:127.0.0.1:${LOCAL_GQL_PORT}" >/dev/null; then
  ssh -fN -R "127.0.0.1:${REMOTE_GQL_PORT}:127.0.0.1:${LOCAL_GQL_PORT}" -p "${SSH_PORT}" "${SSH_HOST}"
fi

echo "==> sync repo (no target/, no params/)"
rsync -avz --exclude target --exclude params -e "ssh -p ${SSH_PORT}" \
  "$(cd "$(dirname "$0")/.." && pwd)/" \
  "${SSH_HOST}:${REMOTE_DIR}/"

echo "==> extract BK set from local docker (writes bk_set.json in prover repo)"
"$(dirname "$0")/extract_bk_set_from_docker.sh" "${DOCKER_NODE:-local_gossip_nodes-node0-1}" \
  "$(cd "$(dirname "$0")/.." && pwd)/bk_set.json"
rsync -avz -e "ssh -p ${SSH_PORT}" \
  "$(cd "$(dirname "$0")/.." && pwd)/bk_set.json" \
  "${SSH_HOST}:${REMOTE_DIR}/bk_set.json"

echo "==> wipe stale proof artefacts on remote (verifier won't re-process seen seqnos)"
ssh -p "${SSH_PORT}" "${SSH_HOST}" "cd ${REMOTE_DIR} && rm -f proofs/proof_*.json proofs/result_*.json && mkdir -p logs proofs state"

echo "==> rebuild daemons natively on n14 (avoids GLIBC mismatch)"
ssh -p "${SSH_PORT}" "${SSH_HOST}" \
  "source ~/.cargo/env && cd ${REMOTE_DIR} && cargo build --release -p bridge-prover-daemon -p bridge-verifier-daemon -p bridge-event-halo2-prover"

GQL="http://127.0.0.1:${REMOTE_GQL_PORT}/graphql"
ssh -p "${SSH_PORT}" "${SSH_HOST}" \
  "cd ${REMOTE_DIR} && pkill -f './target/release/bridge-verifier-daemon' 2>/dev/null || true; \
   pkill -f './target/release/bridge-prover-daemon' 2>/dev/null || true; sleep 1; \
   BRIDGE_GQL_ENDPOINT=${GQL} nohup ./target/release/bridge-verifier-daemon > logs/verifier.log 2>&1 & \
   BRIDGE_GQL_ENDPOINT=${GQL} BRIDGE_BOOTSTRAP_SEQNO=${BOOTSTRAP} nohup ./target/release/bridge-prover-daemon > logs/prover.log 2>&1 &"

echo "started. tail remote logs:"
echo "  ssh -p ${SSH_PORT} ${SSH_HOST} tail -f ${REMOTE_DIR}/logs/prover.log"
echo "  ssh -p ${SSH_PORT} ${SSH_HOST} tail -f ${REMOTE_DIR}/logs/verifier.log"
