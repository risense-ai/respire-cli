#!/bin/sh
# The CLI frontend has no Core SDK or native model runtime payload.
set -eu
apk add --no-cache build-base nodejs pkgconf openssl-dev openssl-libs-static
export OPENSSL_STATIC=1
export CARGO_HOME="/workspace/target/musl-cache/$TARGET/cargo"
export RUSTFLAGS='-C target-feature=+crt-static'
if [ "$TARGET" = 'aarch64-unknown-linux-musl' ]; then
  # Keep vendored C atomics inline; Rust's static musl link omits GCC helpers.
  export CFLAGS_aarch64_unknown_linux_musl="${CFLAGS_aarch64_unknown_linux_musl:-} -mno-outline-atomics"
fi
case "${RELEASE_CACHE_ACTION:-build}" in
  key|pack)
    node scripts/rust-ci-cache.mjs "$RELEASE_CACHE_ACTION" release "$TARGET"
    ;;
  build)
    if [ "${RELEASE_DEPENDENCY_CACHE:-}" = 1 ]; then node scripts/rust-ci-cache.mjs restore release "$TARGET"; fi
    cargo build --release --locked -p respire --bin rsrs --target "$TARGET" --target-dir target/ci
    ;;
  *) echo 'Invalid release cache action' >&2; exit 1 ;;
esac
