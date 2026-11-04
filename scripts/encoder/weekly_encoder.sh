#!/usr/bin/env bash
# Weekly encoder flywheel: build pairs -> LoRA contrastive train -> reembed all docs
# -> evaluate -> atomically swap the dense index only if hit@20 does not regress.
set -uo pipefail

PY="${PYTHON:-python3}"
DATA="${RSRS_DATA_DIR:-$HOME/.rsrs}"
STATE="${RSRS_ENCODER_STATE:-$DATA/encoder}"
BASE="${RSRS_ENCODER_BASE:-$DATA/models/granite-97m-r2}"
INDEX="${RSRS_ENCODER_INDEX:-$STATE/index}"
TOOL="$(cd "$(dirname "$0")" && pwd)/encoder_pipeline.py"
MIN_HIT20="${RSRS_ENCODER_MIN_HIT20:-0.70}"
EPOCHS="${RSRS_ENCODER_EPOCHS:-3}"
mkdir -p "$DATA/logs" "$STATE" "$INDEX"
exec 9>"$STATE/encoder.lock"
flock -n 9 || { echo "$(date -Is) skip: another encoder job is running"; exit 0; }

echo "$(date -Is) weekly encoder start"
"$PY" "$TOOL" --db "$DATA/onememory.db" --base "$BASE" --index-dir "$INDEX" prepare \
  --out "$STATE/pairs.jsonl" >> "$DATA/logs/encoder.log" 2>&1 || exit 1
ADAPTER="$STATE/adapter-$(date +%Y%m%d).pt"
"$PY" "$TOOL" --db "$DATA/onememory.db" --base "$BASE" --index-dir "$INDEX" train \
  --pairs "$STATE/pairs.jsonl" --out "$ADAPTER" --epochs "$EPOCHS" >> "$DATA/logs/encoder.log" 2>&1 || exit 1
"$PY" "$TOOL" --db "$DATA/onememory.db" --base "$BASE" --index-dir "$INDEX" reembed \
  --adapter "$ADAPTER" --pairs "$STATE/pairs.jsonl" --min-hit20 "$MIN_HIT20" \
  >> "$DATA/logs/encoder.log" 2>&1 || exit 1
echo "$(date -Is) weekly encoder done"
