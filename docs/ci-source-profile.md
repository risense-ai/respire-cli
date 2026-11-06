# Source CI profiles and the CLI test-stack exception

Source CI keeps the dev/test defaults at opt-level=0, with debug assertions,
overflow checks, line-table debug information and the existing 90% coverage
gate. The existing sha2 dev-package optimization remains unchanged.

Only `[profile.test.package.respire] opt-level=1` is an approved exception.
On Windows x86_64 with Rust 1.95.0, the actual baseline Clap declarations
generate a 2,148,200-byte `Command::augment_subcommands` stack frame. Current
declarations generate 2,188,856 bytes. Both exceed the measured 2,097,152-byte
default test-thread stack before argument values or business code run.
Boxing the returned enum does not remove these builder temporaries.

Compiling the same current declarations at opt-level=1 reduces that frame to
415,208 bytes. Command construction and parsing then pass on the same default
stack. The actual CLI's existing help/parser and injected-chain parser tests
also pass with this package override and no RUST_MIN_STACK environment value.
This does not claim that the reduced frame is the full CLI binary's exact frame,
or that all capture tests have been rerun.

The contract test permits exactly this test-only package setting. It rejects
other package overrides, changed global profiles, weakened debug settings and
changes to the release profile. It also preserves the existing CI stack value,
including the separated integration lane; this exception does not raise it.

Production release compilation remains unchanged: strip=debuginfo, lto=false,
codegen-units=1 and panic=unwind. The compile matrix receives no source-test
profile environment override. Credential-writing tests still require their
own explicit isolation; this optimization does not authorize running them.


## CLI source and joint Runtime acceptance ownership

- CLI source workspace tests select only respire_spawn, respire_protocol,
  respire_client_host and the commands frontend. Ordinary CLI coverage keeps
  coverage-tests / Coverage (core), its registry command and all three groups.
  These source lanes do not prepare or restore a Core SDK.
- runtime-integration checks out exactly runtime-tests-source.json, prepares the
  matching SDK, and runs the existing Runtime business harness against the
  current run's instrumented CLI and officially installed same-channel Runtime.
  It retains all business module counts, the private credential witness and the
  legacy Runtime workspace / SDK ownership regression. Moving those remaining
  legacy workspace assertions to their owning Runtime repository is unfinished.
- Integration excludes the downloaded source counters before execution. It
  returns only new counters with source archive digest, CLI binary digest,
  repository/source/run/attempt, Runtime source SHA and Runtime version. The
  aggregate validates that binding, merges both integration groups with the
  original three source groups, and retains the unchanged 90% threshold and
  filename exclusions. Integration failure or missing evidence fails the gate.
- Explicit candidate mode retains the existing v2 SDK evidence checks and
  business dispatch in the registry-bound coverage lane. Manual platform builds
  remain native joint checks. Neither path is labelled SDK-free CLI unit testing.
- Candidate protocol v2/v3 migration is UNFINISHED here and belongs to the
  independent v3 owner branch. This change does not migrate or weaken it.
