#!/bin/sh
# Public consumer builds against a validated Core SDK; never builds private ORT/Core sources.
set -eu
apk add --no-cache build-base nodejs pkgconf openssl-dev openssl-libs-static
export OPENSSL_STATIC=1
export CARGO_HOME="/workspace/target/musl-cache/$TARGET/cargo"
export RESPIRE_CORE_SDK_DIR="/workspace/.sdk/$TARGET"
export RUSTFLAGS='-C target-feature=+crt-static'
node scripts/fetch-core-sdk.mjs "$TARGET"
cargo build --release --locked -p respire --bin rsrs --target "$TARGET" --target-dir target/ci

node scripts/stage-core-runtime.mjs "target/ci/$TARGET/release"
