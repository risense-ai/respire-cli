#!/usr/bin/env bash
# Real inference on native Alpine, using only this job's prepared model files.
set -euo pipefail
target="${1:?pass target}"
if [ "$target" != aarch64-unknown-linux-musl ]; then exit 0; fi
bash "$(dirname "$0")/require-native-linux-arm64.sh" "$target"
binary="$(realpath "${2:?pass binary}")"
models="$(realpath "${3:?pass prepared model directory}")"
profile="${4:?pass isolated profile directory}"
test -f "$binary"
test -d "$models"
test -f "$models/tokenizer.json"
test -f "$models/onnx/model_quantized.onnx"
# Match public CPU-container selection: explicit override, profile cache, model dir.
cpu="${RSRS_CPU_OWNED_ORT_FILE:-}"
if [ -z "$cpu" ]; then
  cache="${RSRS_DATA_DIR:-$HOME/.rsrs}/models/bge-m3/onnx/model_quantized.cpu-v1.ort"
  if [ -f "$cache" ]; then cpu="$cache"; else cpu="$models/onnx/model_quantized.cpu-v1.ort"; fi
fi
cpu="$(realpath "$cpu")"
test -f "$cpu"
echo '7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff  '"$cpu" | sha256sum --check --status
runtime="$(realpath "${5:?pass verified musl Runtime binary}")"
runtime_sha256="${6:?pass verified Runtime digest}"
runtime_version="${7:?pass verified Runtime version}"
test -f "$runtime"
test "$runtime" != "$binary"
test "$(basename "$runtime")" = rsrs-runtime
[[ "$runtime_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$runtime_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]
echo "$runtime_sha256  $runtime" | sha256sum --check --status
bundle="$(dirname "$runtime")"
test -f "$bundle/core-runtime.json"
mkdir -p "$profile"
profile="$(realpath "$profile")"
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$binary:/rsrs:ro" -v "$models:/models:ro" -v "$cpu:/cpu-model.ort:ro" -v "$profile:/profile" \
  -v "$bundle:/runtime:ro" \
  -e RSRS_ENGINE=cpu -e RSRS_DATA_DIR=/profile -e RSRS_M3_DIR=/models \
  -e RSRS_CPU_OWNED_ORT_FILE=/cpu-model.ort \
  -e RSRS_RUNTIME_BIN=/runtime/rsrs-runtime -e RSRS_RUNTIME_TRIPLE=aarch64-unknown-linux-musl \
  -e NATIVE_RUNTIME_SHA256="$runtime_sha256" -e NATIVE_RUNTIME_VERSION="$runtime_version" \
  -e RSRS_NO_AUTOSYNC=1 -e RSRS_UPDATE_CHECK=0 \
  alpine:3.23 sh -ec '
    test "$(uname -m)" = aarch64
    test -z "${CORE_SDK_READ_TOKEN:-}"
    test -z "${RSRS_CORE_TEST_MODE:-}"
    test -r /cpu-model.ort
    test -r /models/tokenizer.json
    test -r /models/onnx/model_quantized.onnx
    test -r /runtime/core-runtime.json
    echo "$NATIVE_RUNTIME_SHA256  /runtime/rsrs-runtime" | sha256sum --check --status
    case "$(/runtime/rsrs-runtime --version)" in
      *" $NATIVE_RUNTIME_VERSION") ;;
      *) echo "Runtime version differs from verified installation" >&2; exit 1 ;;
    esac
    /rsrs --direct model probe --json
    /rsrs --runtime-internal --stop --json
  '
