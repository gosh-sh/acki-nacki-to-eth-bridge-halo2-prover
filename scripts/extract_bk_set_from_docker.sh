#!/usr/bin/env bash
# Extract genesis Block Keeper pubkeys from a local docker-compose cluster into bk_set.json.
set -euo pipefail

CONTAINER="${1:-local_gossip_nodes-node0-1}"
OUT="${2:-bk_set.json}"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

idx=0
echo "{" >"$tmpdir/body"
for i in $(seq 0 15); do
  path="/workdir/config/block_keeper${i}_bls.keys.json"
  if ! docker exec "$CONTAINER" test -f "$path" 2>/dev/null; then
    continue
  fi
  pub=$(docker exec "$CONTAINER" cat "$path" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["public"])')
  if [[ $idx -gt 0 ]]; then echo "," >>"$tmpdir/body"; fi
  printf '  "%s": "%s"' "$idx" "$pub" >>"$tmpdir/body"
  idx=$((idx + 1))
  if [[ $idx -ge 5 ]]; then
    break
  fi
done
echo "" >>"$tmpdir/body"
echo "}" >>"$tmpdir/body"

if [[ $idx -eq 0 ]]; then
  echo "no block_keeper*_bls.keys.json found in $CONTAINER" >&2
  exit 1
fi

mv "$tmpdir/body" "$OUT"
echo "wrote $idx signer(s) to $OUT"
