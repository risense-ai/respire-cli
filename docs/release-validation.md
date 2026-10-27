# Release validation

New releases target Windows x64, Linux x64 (GNU and musl), and macOS ARM64.
Linux ARM64 and Windows ARM64 packages are no longer published. Historical
published assets remain available; Intel macOS was already unsupported.
The paired Core SDK still validates its own seven-target compatibility contract.

DEV gates: exact-source workspace unit tests and existing coverage checks, one Release build for each of four targets, native executable startup, real quantized CPU inference on macOS, pinned SDK digests, and consistent artifacts for all five scoped npm packages.

`rsrs-cli` is the primary public npm install entry. Protocol 2 separates two
states; neither state can substitute for the other:

- **accepted**: all four platform packages, the scoped umbrella and `rsrs-cli`
  have explicit successful npm submission acknowledgements, or their existing
  exact public bytes have been confirmed. Local pack SHA-512/SHA-1, package
  versions and exact dependencies remain mandatory. The umbrella follows all
  platform acknowledgements; alias follows the scoped receipt. The Release
  becomes public only after the exact alias publisher job succeeds, all required
  acknowledgements exist, and the source attempt, tag and twelve assets match.
- **verified**: the separate `Verify public npm publication` workflow confirms
  public metadata, install-index resolution and tarball digests, then performs
  an isolated Linux x64 GNU public install. It checks alias/scoped/native
  versions, the native binary hash, `--version` and `--help`. This proves the
  GNU install only; it does not claim native installation on other systems.

`scoped-accepted-RUN-ATTEMPT` and `alias-accepted-RUN-ATTEMPT-CHILD-ATTEMPT`
receipts bind the repository, workflow, selected source SHA (which may differ
from the dispatch workflow SHA), exact attempts, version, channel, release ID,
local package digests, assets and actual npm acknowledgements. An accepted
receipt never contains fabricated registry metadata or installation evidence.
The parent `publication-accepted` report explicitly leaves public verification
pending. The independent `publication-verified` report records actual content
and installation proof with its completion time.

`npm-alias.yml` retains its Trusted Publishing identity and permissions and
starts on Release `in_progress`. Its read-only early wait holds no publication
lock or OIDC permission. Its writer checks out the receipt's selected source,
uses the existing alias lock and never waits for the parent to complete. The
parent observes the exact successful publisher job and durable accepted receipt,
not the whole child workflow or background verifier. Background verification
starts after parent completion, including a failure after publication, has read-only permissions, holds no
publication lock and can validate an immutable completed source attempt. All
write operations still require the active current source attempt. A failed parent can only produce a verified report if its exact public Release, complete accepted receipts and public content/install all validate; it still cannot authorize artifact cleanup. Protocol 1
and its integrated installation barrier remain for historical recovery.

A successful npm process must have exit code zero, no spawn error and no signal.
Only that explicit acceptance avoids propagation waiting. Failed or uncertain
submissions are reconciled by bounded read-only content verification; they are
never blindly repeated. Submission journals preserve intent before the write
and each acknowledgement afterward. A rerun must reconcile interrupted earlier
attempts; missing evidence fails closed. Public read failures cannot be reported
as acceptance. Existing matching immutable versions are skipped without tag
changes. DEV uses `dev`, stable uses `latest`, and tag rollback remains forbidden.
A failed required package prevents overall publication success; partial accepted
versions remain immutable and the Release remains draft.

The publication target is ten minutes from the publication trigger to a public
Release and all required npm acknowledgements. Registry/CDN propagation and
public installation are measured separately and do not block that state. The
accepted report records the actual Release run creation and acceptance times;
this is not a claim that validation, runner queues or external npm latency fit
ten minutes. Also report source-to-complete-validation time and, if validation
is prepared ahead, the separate ready-artifact-to-publication interval. Only
exact merged source/version/platform/toolchain/SDK-lock/content-bound validation
may be reused; different or untrusted PR artifacts cannot authorize publication.
No measured ten-minute result is claimed by this protocol change alone.

To resume that same version, rerun the failed publication job only while its
original plan, build artifacts and required receipts remain available within the
one-day retention window. A fresh run attempt requires fresh ready/alias receipts;
stale attempts cannot finish publication. Once the evidence expires, stop and
diagnose the remaining draft and npm state before separately authorized recovery;
never substitute a version string or successful run status for missing evidence.
Do not use a full workflow rerun as same-version recovery: rerunning `plan` can allocate a different DEV version.
Waits are bounded (four hours for initial scoped readiness, fifteen minutes for
a set of public tarball checks, forty-five minutes for matching alias success).
A failed or timed-out barrier never makes a draft public. The workflow-run event
and OIDC handoff require a real release after deployment to validate end to end;
local tests simulate the registry and validate workflow/receipt contracts without
publishing test versions.

Validation-only runs, failed/skipped publication and explicitly scoped historical
ARM64 repairs do not emit ready receipts. Old source refs without the publication
protocol are refused before any scoped npm write. To recover a missing alias for
an already-public historical release, explicitly dispatch `npm-alias.yml` with
`version` and `release_run`; its legacy recovery path requires successful source
publication and a public release. It is not an automatic bypass of this barrier.

## Client sync payload retention

The client retains current memories, one current remote snapshot per memory, and
unconfirmed operations or unresolved incoming data. Completed transport payloads
are reclaimed; processed conflicts retain only their small resolution receipts.
The server sync protocol, operation identities and cursor commit rules are unchanged.

Opening an existing library migrates remote snapshots from the old inbox before
reclaiming history. The same cleanup runs before and after sync, including before
a network failure can leave the previous round's completed payloads behind.
When free SQLite pages total at least 16 MiB and one quarter of the database,
automatic VACUUM and WAL truncation return that space to the filesystem.
An active reader or writer can defer compaction until a later maintenance pass.
Disk-full and I/O compaction failures log a warning and defer compaction rather
than preventing library access; reclamation errors still fail explicitly.
An explicit snapshot reset saves the previous current heads for recovery after
a server backup restore. Matching heads or explicit restoration reclaim these
recovery payloads; the completed edit history is not retained.
Current content, pending operations, undecodable data and unresolved conflicts
must survive migration; sync and memory revision tokens must remain unchanged.

Remote history queries return a bounded in-memory view without caching the
account's history in the inbox. Restoring a reclaimed version fetches the
requested operation or revision through the existing remote history protocol.

## Actions artifact retention and recovery

All workflows explicitly retain Actions artifacts for one day after upload,
including accepted and verified publication receipts and legacy `scoped-ready` / `alias-ready` receipts.
Build inputs, cross-job transfers, and publication receipts are still uploaded;
consumers, validation gates, publication locks, and digest checks are unchanged.
This policy does not change GitHub Release assets, published npm packages, or
Actions cache and workflow-log retention.

After an artifact expires or is deleted, failed-job reruns that need original
build inputs, the integrated publication handshake that needs its matching
`scoped-ready` / `alias-ready` receipts, and historical short-package repair that
needs the original `npm-release-validation` receipt are not guaranteed to work.
Supplying a version does not replace those receipts. Long publication queues can
also outlive the one-day window. Missing or expired evidence must fail closed: never skip digest,
source, regression, receipt, or publication checks to work around retention.
A full workflow rerun can allocate a different DEV version and is not guaranteed
to recover the same version. Diagnose the remaining draft and public package
state before a separately authorized recovery or new release.

The targeted `migration-keyring-check.yml` workflow also downloads
`cli-release-${{ matrix.target }}` from its `release_run_id`; expiry prevents
that diagnostic from verifying the original binary. For a new candidate,
separately authorize a fresh, non-publishing `release-validation.yml` run. Its
dispatch workflow ref and `ref` input must resolve to the same source commit,
because the targeted consumer checks the producer's `head_sha`. Wait for all
required platform builds and `npm-dry-run` to succeed, then use the new run ID
for targeted migration before its artifacts expire. This validates a freshly
built candidate, not the deleted original bytes. Preserve all source, version,
and digest checks; if the original artifact identity is required, stop and
report that evidence as unavailable rather than substituting a newer binary.

Deletion or expiry also removes downloadable diagnostic reports and publication
receipts; run status and logs are not a substitute for those files. An artifact
cleanup is not permission to delete Release assets or npm versions.

Only version allocation and publication share a serial lock. Allocation reserves the DEV number in an unpublished draft. The existing version script counts drafts to prevent collisions. Failed drafts remain available for diagnosis. Full regression does not hold this lock. Workflow or documentation changes alone do not publish a DEV.

Four-target builds run in Release. The separate compile matrix is manual. CLI tests run once through the existing coverage command; other workspace tests run separately. musl builds reuse the existing cache. macOS reuses the model cache while still checking model files and performing real inference.

Historical upgrades on four targets, full CLI regression on three systems, and DEV API regression run independently. They verify source, version, and digests of the original build artifacts without compiling again. They do not block DEV publication. Report failures; do not declare a DEV fully validated until these checks succeed.

Stable publication waits for successful historical upgrades on all four targets, all three system regressions, and API regression. Failed, cancelled, skipped, or missing results block publication. The upgrade script discovers every stable release from 1.0.6 onward. There is no stable 1.0.6 artifact, so the actual historical DEV baseline is also retained. Each new stable release automatically joins future upgrade validation.

Manual Release validation runs all native upgrade checks by default. After DEV publication, verify the public install, exact platform package versions, runtime status, and actual regressions for the related issues. Never count unexecuted checks as passed.

When a DEV must pass full acceptance before publication, merge with `[manual-release]` in the commit message to suppress automatic Release allocation while keeping push CLI CI enabled. Then dispatch Release for the exact merged source with `publish=true`, `full_regression_before_publish=true` and the requested unpublished `dev_version`. Publication waits for all four native upgrades, all three system regressions and API checks from that same run; builds and regressions are not repeated. The default fast DEV order is unchanged.

For an explicitly requested DEV number, manual Release accepts `dev_version` in `X.Y.Z-dev.N` format. Its base can differ from the source manifest, so a published `1.0.12` baseline can produce the requested `1.0.13-dev.N` artifacts. It must have no Git tag or published package on any of the five scoped npm packages. Only an empty, unpublished DEV draft can be resumed after its previous release run finishes; preserve the failed run and reports. Draft notes record their owner run, and an active owner blocks resumption. Legacy drafts without an owner marker require all other Release runs to finish first. The corrected source still passes the normal builds and regression gates. Omit the input for automatic allocation. Stable releases reject this input.

## Independent source and migration checks

Normal CLI CI runs Rust workspace/90% coverage and packaging/workflow/fixture
contracts on independent runners. `check-complete` fails unless both lanes
succeed, including unexpected skips. Release's exact-source push-CI check still
requires the entire CLI CI run to succeed; adding a job does not automatically
configure a GitHub required branch check.

Windows and macOS migration fixtures run independently of base cloud sweeps,
with separate runners, profile roots and owned random native keyring entries.
Their join jobs wait for both successful producer groups. On each native
platform, the existing migration gate checks both reports against the original
verified build metadata's exact SHA/version/target/binary digest. Fixture success
alone cannot replace the base report, and base success cannot replace migration.
Linux supplements and their model/outbox dependencies keep their ordering.

New accepted receipts declare the full regression inventory: four native
upgrade lanes, three system sweeps, two native migration fixtures, two native
join gates and the API check. Publication and cleanup validate every declared
lane; failure, cancellation, skip, missing or duplicate targets cannot authorize
success. Older receipts retain their original strict inventory rather than
retroactively requiring jobs that did not exist. This changes overlap, not test
coverage or the ten-minute performance claim; timings require an actual run.
