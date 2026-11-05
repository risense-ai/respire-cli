# G1 execution evidence v2

Ordinary source CI does not request a frozen candidate and therefore skips only
the candidate-specific `required-tests` job. Its workspace tests, three coverage
groups, 90% coverage threshold and independent contracts must still pass. If any
candidate input is supplied, report verification is mandatory; partial inputs,
missing reports, failed verification or a skipped verifier fail the aggregate.
Candidate inputs cannot be combined with research, published-native, artifact or
version-upgrade focused modes. The strict verifier and its required registry
entries remain mandatory; no missing-report exception is permitted.
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

The two implemented CLI entries remain source tests. They do not satisfy
published-asset or eight-target native acceptance. Runtime 8, Client2 4, and
CLI 1 missing entries remain missing. No status, target, case, or reason is
changed by this format migration.

Raw source logs use a separate `evidence_class: source-raw` context with
`gate: not-evaluated`; their schema 1 is not an execution-report schema.
They must never be accepted as v1 or v2 passing reports.

The CLI producer now enables `prepare`, candidate-bound `captureCoverage`,
`buildReports`, and `produce` for Linux X64 Coverage (core). These produce only
the two mapped source-test reports. Ordinary runs without candidate inputs
continue to capture raw logs with null candidate/SDK and `gate: not-evaluated`.
Neither mode certifies G1.

### Workflow input and artifact contract

The parent-owned `ci.yml` wiring uses three `workflow_dispatch` inputs:
`required_candidate_run_id`, `required_candidate_artifact_id`, and
`required_candidate_sha256`. The core coverage job passes them as
`REQUIRED_CANDIDATE_RUN_ID`, `REQUIRED_CANDIDATE_ARTIFACT_ID`, and
`REQUIRED_CANDIDATE_SHA256`. Before downloading, the workflow requires either
all three inputs or none, validates positive integer ID strings and a lowercase
64-hex digest, and restricts candidate inputs to the manual event. Its GitHub API
check requires the artifact to belong to the current repository, have the exact
artifact ID, remain unexpired, and have `workflow_run.id` equal to the supplied
run ID and `workflow_run.head_sha` equal to the current source SHA.

For an ordinary run, the Node process calling `captureCoverage` must have all
three `REQUIRED_CANDIDATE_*` variables absent. GitHub job-level expressions may
create empty environment variables even when no inputs were supplied. After the
workflow has verified the all-absent input case, the caller must delete those
three variables from its own `process.env` before capture. An empty variable is
still a candidate-mode trigger; the producer deliberately does not downgrade it
to ordinary raw. The workflow caller now removes them only when all three are
empty. Four pure wrapper checks cover empty, absent, complete and partial inputs;
partial inputs are never silently downgraded to ordinary raw.

`actions/download-artifact` selects that exact artifact ID and run ID into
`$RUNNER_TEMP/required-tests-candidate-input`. The directory must contain only
two ordinary files: `candidate.json` and `sdk.tar.gz`. The candidate digest is
the SHA-256 of the exact candidate bytes, including whitespace. The compressed
SDK archive must be supplied by that artifact; an extracted cache directory or
a candidate/lock digest cannot replace the archive bytes.

After SDK fetching has set `RSRS_CORE_SDK_DIR` to the current build directory,
the workflow runs `node scripts/produce-required-tests.mjs prepare`. It then
captures coverage, uploads the raw directory with step ID `required-raw`, and
runs `node scripts/produce-required-tests.mjs produce` with
`REQUIRED_RAW_ARTIFACT_ID` set to `steps.required-raw.outputs.artifact-id`.
This ID must be a positive integer string that can be represented exactly as a
JSON number; it is never inferred from a name or supplied as a placeholder.
The final report upload is named
`required-tests-report-${run_id}-${run_attempt}` and contains the exact candidate
bytes plus `reports/cli.release-metadata-dual-digest.json` and
`reports/cli.release-metadata-legacy-mapping.json`.

### Producer binding and refusal behavior

`prepare` requires the current Linux X64 `coverage-tests` context and both input
IDs. It calls `verifyCandidate`, `auditSdkDirectory`, and `verifySdk` against
the checked-out SDK lock. It saves the exact candidate bytes and a schema 2
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
and evidence mode, the core `cargo llvm-cov --locked -p respire --no-report
--lib --bins --examples` prefix, and only unique `--test <name>` pairs afterward.
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
