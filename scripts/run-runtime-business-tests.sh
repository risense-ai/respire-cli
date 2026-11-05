#!/usr/bin/env bash
set -euo pipefail

phase='coverage environment'
trap 'status=$?; printf "::error::Runtime business runner failed during %s at line %s (exit %s)\n" "$phase" "$LINENO" "$status" >&2; exit "$status"' ERR

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${RSRS_RUNTIME_TEST_RUNNER:?Runtime business runner is required}"
: "${RUNTIME_BUSINESS_MODULES:?Runtime business modules are required}"

coverage_dir="$PWD/target/llvm-cov-target"
CARGO_LLVM_COV_TARGET_DIR="$coverage_dir" cargo llvm-cov show-env --sh > "$RUNNER_TEMP/cli-coverage.env"
source "$RUNNER_TEMP/cli-coverage.env"

phase='instrumentation validation'
# cargo-llvm-cov 0.9 defaults to a rustc wrapper instead of public RUSTFLAGS.
if [[ "${RUSTFLAGS:-}${CARGO_ENCODED_RUSTFLAGS:-}" != *instrument-coverage* ]]; then
  if [[ "${__CARGO_LLVM_COV_RUSTC_WRAPPER:-}" != 1 || -z "${RUSTC_WRAPPER:-}" || "${__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS:-}" != *instrument-coverage* ]]; then
    printf '::error::Coverage instrumentation is missing from both direct flags and the active rustc wrapper\n' >&2
    exit 1
  fi
fi
if [[ "${LLVM_PROFILE_FILE:-}" != "$coverage_dir/"* ]]; then
  printf '::error::LLVM_PROFILE_FILE must remain under the existing instrumented CLI coverage directory\n' >&2
  exit 1
fi

phase='existing instrumented CLI identity'
export RSRS_CLI_BIN="$coverage_dir/debug/rsrs"
export RSRS_CLI_SOURCE_DIR="$PWD"
export RSRS_CLI_SOURCE_SHA="$(git rev-parse HEAD)"
test -x "$RSRS_CLI_BIN"
original_cli="$(sha256sum "$RSRS_CLI_BIN")"
unset GH_TOKEN GITHUB_TOKEN

for module in $RUNTIME_BUSINESS_MODULES; do
  phase="business module $module"
  "$RSRS_RUNTIME_TEST_RUNNER" "$module::" --test-threads=1
done

phase='unchanged instrumented CLI identity'
test "$(sha256sum "$RSRS_CLI_BIN")" = "$original_cli"
