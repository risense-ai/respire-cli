#!/usr/bin/env bash
# Daily online reranker refresh: BM25 base + residual features from real adoption.
# Cheap (no model weights, no re-embedding); runs against the user's local store.
set -uo pipefail

BIN="${RSRS_BIN:-}"
if [ -z "$BIN" ]; then
  for candidate in "$HOME/Documents/respire/respire-cli/target/release/rsrs" \
                   "$HOME/Documents/respire/respire-cli/target/debug/rsrs" \
                   "$HOME/.rsrs/bin/rsrs"; do
    [ -x "$candidate" ] && BIN="$candidate" && break
  done
fi
DATA="${RSRS_DATA_DIR:-$HOME/.rsrs}"
STATE="${RSRS_ENCODER_STATE:-$DATA/encoder}"
mkdir -p "$DATA/logs" "$STATE"
exec 9>"$STATE/rerank.lock"
flock -n 9 || { echo "$(date -Is) skip: another rerank job is running"; exit 0; }

# The installed runtime must understand `learn`; otherwise wait for the upgrade.
if ! RSRS_DATA_DIR="$DATA" "$BIN" learn status --json >/dev/null 2>&1; then
  echo "$(date -Is) skip: current runtime does not expose learn (upgrade required)"
  exit 0
fi

echo "$(date -Is) daily rerank start"
RSRS_DATA_DIR="$DATA" timeout 300 "$BIN" learn train --from-labels --limit 5000 --epochs 1 --json >> "$DATA/logs/rerank.log" 2>&1 || true
echo "$(date -Is) daily rerank done"
RSRS_DATA_DIR="$DATA" "$BIN" learn status --json >> "$DATA/logs/rerank.log" 2>&1 || true
