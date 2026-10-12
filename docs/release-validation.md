# Release validation

New releases target Windows x64, Linux x64 (GNU and musl), and macOS ARM64.
Linux ARM64 and Windows ARM64 packages are no longer published. Historical
published assets remain available; Intel macOS was already unsupported.
The paired Core SDK still validates its own seven-target compatibility contract.

DEV gates: exact-source workspace unit tests and existing coverage checks, one Release build for each of four targets, native executable startup, real quantized CPU inference on macOS, pinned SDK digests, and consistent artifacts for all five scoped npm packages.

`rsrs-cli` is the primary public npm install entry and is part of the Release
success gate. `release.yml` publishes and verifies all five scoped packages,
including actual public tarball SHA-512 and SHA-1 checks. It uploads a
`scoped-ready-RUN-ATTEMPT` receipt tied to the repository, workflow, selected
source SHA (which can differ from the dispatch workflow SHA), version, channel,
draft release ID, package digests and all twelve validated assets.

`npm-alias.yml` starts on Release `in_progress`. Its read-only waiting job holds
no publication lock or OIDC permission. Once ready, its publisher acquires the
existing short-package lock, checks out the selected source SHA, rechecks all
five public packages, publishes the exact-version alias, and verifies a fresh
public npm install on Linux x64 GNU. It checks the resolved alias, scoped CLI,
native version, native binary hash, and the installed `rsrs --version` and
`--help`. This install check does not claim native installation on other systems;
the four platform tarballs are independently verified.

Only after the exact alias run/attempt and publisher job succeed with a matching
`alias-ready` receipt does the original Release publisher recheck all six
registry versions, the draft assets, source tag and current attempt, then make
the GitHub release public. Both publishers retain their existing workflow names,
Trusted Publishing identities and permissions. The parent holds its existing
publication lock while awaiting the alias; the alias publisher never waits for
the parent to finish or for its draft to become public. The unlocked early wait
prevents two overlapping Releases from acquiring these locks in opposite order.

Visibility waits tolerate registry 404 propagation but fail closed on content
mismatch or other registry errors. Existing matching immutable versions are
verified and skipped without changing distribution tags; missing versions are
published once. An uncertain npm submission is followed only by bounded public
verification, never a blind second publish. DEV uses `dev`, stable uses `latest`,
and neither publisher moves a tag backward. npm multi-package publication is
not atomic: a failed alias may leave some or all scoped versions public, while
GitHub remains draft and the Release fails honestly.

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

## Actions artifact retention and recovery

All workflows explicitly retain Actions artifacts for one day after upload,
including `scoped-ready` and `alias-ready` publication receipts.
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
