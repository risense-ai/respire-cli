#!/usr/bin/env bash
# Daily online reranker refresh: BM25 base + residual features from real adoption.
# Cheap (no model weights, no re-embedding); runs against the user's local store.
set -uo pipefail

BIN="${RSRS_BIN:-$HOME/.rsrs/bin/rsrs}"
for tool in flock timeout date; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: required tool not found: $tool" >&2; exit 1; }
done
if [ ! -x "$BIN" ]; then
  echo "error: executable not found: $BIN (set RSRS_BIN to a legacy server experimental CLI)" >&2
  exit 1
fi
DATA="${RSRS_DATA_DIR:-$HOME/.rsrs}"
STATE="${RSRS_ENCODER_STATE:-$DATA/encoder}"
mkdir -p "$DATA/logs" "$STATE"
exec 9>"$STATE/rerank.lock"
flock -n 9 || {
  status=$?
  if [ "$status" -eq 1 ]; then
    echo "$(date '+%Y-%m-%dT%H:%M:%S%z') skip: another rerank job is running"
    exit 0
  fi
  echo "error: flock failed with status $status" >&2
  exit "$status"
}

# The experimental legacy CLI must expose `learn`.
if ! RSRS_DATA_DIR="$DATA" "$BIN" learn status --json >/dev/null 2>&1; then
  echo "error: learn status failed; RSRS_BIN must select a legacy server experimental CLI" >&2
  exit 1
fi

echo "$(date '+%Y-%m-%dT%H:%M:%S%z') daily rerank start"
RSRS_DATA_DIR="$DATA" timeout 300 "$BIN" learn train --from-labels --limit 5000 --epochs 1 --json >> "$DATA/logs/rerank.log" 2>&1 || true
echo "$(date '+%Y-%m-%dT%H:%M:%S%z') daily rerank done"
RSRS_DATA_DIR="$DATA" "$BIN" learn status --json >> "$DATA/logs/rerank.log" 2>&1 || true
