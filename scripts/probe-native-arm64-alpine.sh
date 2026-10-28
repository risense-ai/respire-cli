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
mkdir -p "$profile"
profile="$(realpath "$profile")"
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$binary:/rsrs:ro" -v "$models:/models" -v "$profile:/profile" \
  -e RSRS_ENGINE=cpu -e RSRS_DATA_DIR=/profile -e RSRS_M3_DIR=/models \
  -e RSRS_NO_AUTOSYNC=1 -e RSRS_UPDATE_CHECK=0 \
  alpine:3.23 sh -ec '
    test "$(uname -m)" = aarch64
    test -z "${CORE_SDK_READ_TOKEN:-}"
    test -z "${RSRS_CORE_TEST_MODE:-}"
    /rsrs --direct model probe --json
  '
