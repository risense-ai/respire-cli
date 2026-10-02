#!/usr/bin/env bash
# Run on a Linux host of the target architecture with Docker installed.
set -euo pipefail

target="${1:?pass the Rust musl target}"
case "$target:$(uname -m)" in
  x86_64-unknown-linux-musl:x86_64|aarch64-unknown-linux-musl:aarch64) ;;
  *) echo "unsupported target/host: $target/$(uname -m)" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/target/musl-cache/$target"
docker run --rm \
  -v "$root:/workspace" -w /workspace \
  -e TARGET="$target" \
  rust:1.95.0-alpine3.23 \
  sh scripts/build-linux-musl-container.sh

binary="$root/target/ci/$target/release/rsrs"
# A static ELF must have neither a dynamic loader nor shared-library imports.
if readelf -l "$binary" | grep -q INTERP; then
  echo 'musl binary unexpectedly requires an ELF interpreter' >&2
  exit 1
fi
if readelf -d "$binary" | grep -q NEEDED; then
  echo 'musl binary unexpectedly requires shared libraries' >&2
  exit 1
fi
"$binary" --version
# Exercise the same artifact on a musl userspace as well as the Ubuntu host.
docker run --rm -v "$binary:/rsrs:ro" alpine:3.23 /rsrs --version
