# G1 execution evidence v2

Ordinary source CI runs the workspace tests and independent contracts. The
manual G1 source workflow binds its evidence to a frozen candidate. Incomplete
inputs fail before source execution. The strict verifier still requires every
registered entry and complete candidate-bound reports.
A successful source CI run is not G1 acceptance. CLI 1.0.21-dev.5 defers Intel
macOS and releases seven platforms. Historical candidates used eight targets;
current release acceptance uses seven, with Intel macOS deferred. This scope
change does not certify a candidate or complete G1; real current-scope execution
evidence is still required. Release planning rejects `latest` and `stable`
channels until complete G1 verification is implemented and separately authorized.
DEV publication retains its exact-source CI and seven real native gates.

This format is a contract, not a frozen candidate or an execution result.
Candidate schema 1 and required-execution/v1 reports are rejected. The registry
itself stays schema 1; every entry uses `report_schema: required-execution/v2`.
Changing that label does not implement a missing test or pass a gate.

## Frozen candidate

A candidate has `schema: 2`, `frozen: true`, `gate: G1`, and
`components.runtime`, `components.cli`, and `components.client2`.
Each component retains its exact `source_sha`, `version`, and nonempty
`artifacts.<target>` map. Each artifact retains the product
`archive_sha256` and `binary_sha256` and adds `native_sdk`.

For Runtime and CLI, `native_sdk` is an object with exactly these fields:

| Field | Meaning |
|---|---|
| `version` | Native Core SDK version, nonempty text |
| `manifest_sha256` | SHA-256 of the exact native SDK manifest bytes |
| `archive_sha256` | SHA-256 of the exact compressed native SDK archive bytes |

SDK digests are 64 lowercase hexadecimal characters. The component and target
are supplied by the enclosing map; they must not be inferred from another row.
Current Runtime dev.21 and CLI dev.20 identities can coexist. Archives and
manifests can differ across targets even when the SDK version is equal.

Client2 currently builds directly with Go and does not consume the native Core
SDK. Every Client2 artifact must contain `native_sdk: null`. Omitting the key
is invalid. This null says nothing about the Runtime that Client2 controls.

There is no global `sdk` field in v2; its presence is rejected. The Rust wrapper
crate (currently `respire_core_sdk` 2.0.0-dev.4) is a different dependency.
Its source/version and lock files are bound by the component source SHA.
A wrapper crate archive or version must not replace a native SDK identity.

## required-execution/v2 report

The report has numeric `schema: 2`. Existing bindings remain required:
`test_id`, `target`, `coverage`, `status: passed`, nonempty passed `cases`,
`source_sha`, `repository`, `run_id`, `run_attempt`, `candidate_sha256`,
`job_name`, `artifact_id`, and `artifact_name`.

The report adds `actual_native_sdk`. For Runtime and CLI it must have the same
three fields as the candidate and match
`components.<registry owner>.artifacts.<report target>.native_sdk` exactly.
Client2 must explicitly report null. A report-level `sdk` field is rejected.

The producer must derive the actual identity from the SDK used for that run:
read and hash the manifest and archive bytes, validate manifest version/target,
and bind the installed payload to the manifest and checked-out lock.
Copying candidate fields into `actual_native_sdk` is not verification.
The verifier compares identities; that comparison alone cannot prove that a
producer read or loaded the actual bytes.

Keep the exact candidate bytes. Hash those bytes, not reserialized JSON.
Upload raw evidence in its producing test job before creating the report bundle.
The verifier still requires the current source/run/attempt, a successful mapped
job, non-expired raw artifact identity and creation time inside that job,
all mapped cases including mandatory children, and every required target.
No frozen candidate means no passing execution report.

## Scope and current producer state

The CLI registry has two source tests and a native package matrix. Each
matrix job installs the frozen candidate tarballs offline on its target OS
and architecture. The job hashes the installed executable, runs it through
the launcher, and checks a fresh Runtime inventory. The CLI evidence check
requires all eight native reports and both source reports from one attempt.
Full release regression and cross-product G1 remain separate checks.

Raw source logs use a separate `evidence_class: source-raw` context with
`gate: not-evaluated`; their schema 1 is not an execution-report schema.
They must never be accepted as v1 or v2 passing reports.

The CLI producer now enables `prepare`, candidate-bound `captureCoverage`,
`buildReports`, and `produce` for Linux X64 Coverage (core). These produce only
the two mapped source-test reports. Ordinary runs without candidate inputs
continue to capture raw logs with null candidate/SDK and `gate: not-evaluated`.
Neither mode certifies G1.

### Workflow input and artifact contract

Run `g1-cli-freeze-input.yml` on the same trusted-main commit to store the
reviewed inventory. Supply the original JSON and its SHA-256. The workflow
checks the source identity and records the exact bytes. Its successful run
and artifact IDs are inputs to the G1 source workflow. Recording the inventory
does not validate the product assets or certify G1.

The opt-in `g1-cli-source-evidence.yml` workflow produces the two CLI source
reports on trusted main. Its dispatch inputs are `candidate_run_id`,
`candidate_artifact_id` and `candidate_sha256`. The workflow keeps the
`coverage-tests` producer identity and runs the Runtime installer fixture
module. Supply `cli_package_run_id` to also run the native matrix. The source
job verifies the successful main Release run, exact source, producing npm job
and live artifact before the matrix downloads the selected archives. Leave
the optional input empty to collect source reports alone. The native matrix
requires `components.cli.launcher_archive_sha256` in the frozen candidate,
along with the existing per-platform archive and executable digests.

The core job passes the inputs as `REQUIRED_CANDIDATE_RUN_ID`,
`REQUIRED_CANDIDATE_ARTIFACT_ID`, and `REQUIRED_CANDIDATE_SHA256`. Before
downloading it verifies the positive IDs, SHA-256 format, trusted main ref and
the GitHub artifact's run, source SHA and expiration state.

`actions/download-artifact` selects the exact artifact ID and run ID into
`$RUNNER_TEMP/required-tests-candidate-input`. The directory must contain only
an ordinary `candidate.json` file. The digest covers the original JSON bytes,
including whitespace. These frontend installer tests use no native Core SDK.

The workflow calls `prepare` before executing the tests, uploads raw evidence
and passes the resulting actual artifact ID to `produce`. The report upload
contains the original candidate and the two structured CLI source reports.

### Producer binding and refusal behavior

`prepare` requires the current Linux X64 `coverage-tests` context and both input
IDs. It verifies the candidate identity and the frontend's null native SDK
binding, then saves the exact candidate bytes and a schema 2
`preflight.json` beneath `$RUNNER_TEMP/required-tests-raw-cli-core`. The preflight
binds repository, source SHA, run ID, attempt, job, target, both candidate input
IDs, candidate hash, resolved SDK path, SDK real path, computed SDK identity, and
start/completion timestamps. It uses exclusive writes and refuses an already
existing raw directory, even when the directory is empty. A standalone prepare
rerun therefore cannot overwrite a preflight or relabel previously captured raw.

`captureCoverage` treats the presence of any of the three candidate environment
variables (even an empty one), the candidate input directory, or a retained
candidate/preflight as candidate mode. Before spawning it requires a complete
prepare, reruns all input/SDK checks, compares the current context, input IDs,
paths, digests and retained candidate bytes with the preflight, and validates the
source command. Missing prepare, changed inputs, a different SDK directory,
stale run/attempt, and existing logs/execution all fail before spawn. Its execution
record binds the original preflight byte hash, candidate, actual SDK, paths and
IDs with `evidence_class: candidate-source` and `gate: not-evaluated`.

`produce` repeats current input/SDK verification and compares the retained bytes,
original preflight hash and execution bindings. `buildReports` requires the
exact current context, exact three-field native SDK shape, recognized schemas
and evidence mode, and the core `cargo llvm-cov --locked -p respire --no-report
--lib --bins --examples` prefix. The command can select unique integration test
targets or the fixed installer fixture module.
It verifies both log hashes, successful exit with no signal/error, complete
suite counts, and exactly one passed result for each required source case.
Empty output, failed output and contradictory counts fail. Timestamps must be
valid UTC ISO strings and ordered prepare start <= prepare completion <=
execution start <= execution completion <= current time. Raw records are never
promoted. Both v2 reports retain `coverage: source-test`, not G1 acceptance.

`verifySdk(archive, manifestBytes, lockEntry, expectedNativeSdk)` is independently
usable as a pure byte verifier for CLI `x86_64-unknown-linux-gnu`. Pass the current
checked-out `sdk/core-sdk.lock.json` target entry and the verified candidate's
`components.cli.artifacts.x86_64-unknown-linux-gnu.native_sdk`; the function does
not load a lock or select an owner on the caller's behalf. It checks the parsed
manifest version/target, both computed digests against the lock and candidate,
and exact archive manifest/payload membership and per-file hashes. It reuses
`inspectArchive` to reject unsafe paths, links, duplicate members and malformed
tar structures. Only parent directories of expected files are allowed.
Its returned version comes from the parsed manifest; both returned digests are
computed from the supplied bytes, never copied from the candidate.

The enabled path audits the extracted SDK and then calls this byte verifier.
The audited SDK path is passed unchanged through the child environment and
bound in execution. Pure verification alone does not prove that a real native
build loaded the SDK. Workflow wiring belongs to the parent change; the producer
change does not edit a workflow or registry.

The existing `node scripts/test-required-tests.mjs` self-check constructs minimal
gzip/ustar fixtures without downloading an SDK. It covers successful computed
identity, lock/candidate/owner/target/version/digest mismatches, archive manifest
differences, duplicate/extra/missing/corrupt payloads, unsafe members, and agreement
with the extracted-directory audit. It also extends the existing pure tests with
a synthetic installed SDK and lock under workspace `.verification`, a successful
prepare/capture/produce chain, and refusal cases for missing prepare, stale
context, changed IDs/paths/bytes, absent hash, invalid artifact IDs, raw promotion,
invalid modes, commands, timestamps, logs, exits and counts. Capture tests replace
the Node child-process module binding; they never execute Cargo or host rsrs.
These synthetic checks are not native SDK, CI, or release acceptance evidence.

The two inline workflow steps passed 16 pure mock checks, and the environment
wrapper passed four more. The parent also reran the producer's 118 pure checks.
No actual GitHub API request, artifact transfer, CI job, native build or G1 run
was performed for this producer validation.

The downstream native aggregator source now accepts this v2 contract. Its pure
synthetic self-checks do not prove actual SDK byte use, a complete eight-target
producer, or real CI/native execution. No final candidate has passed G1.
