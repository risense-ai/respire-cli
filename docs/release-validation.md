# Release validation

DEV gates: exact-source workspace unit tests and existing coverage checks, one Release build for each of seven targets, native executable startup, real quantized CPU inference on macOS, pinned SDK digests, and consistent artifacts for all eight npm packages.

`rsrs-cli` is the primary public npm install entry. After each completed Release,
`npm-alias.yml` automatically checks successful `plan` and `publish` jobs, reads
the version from that run's npm receipt, and verifies the matching public scoped
CLI digest and public GitHub release before publishing the exact-version entry.
DEV versions use `dev`; stable versions use `latest`. Validation-only and failed
publication runs are skipped. Existing identical versions are not republished
and their distribution tags are left unchanged. To recover an omitted entry,
dispatch this same trusted-publisher workflow with `version` and `release_run`.

Only version allocation and publication share a serial lock. Allocation reserves the DEV number in an unpublished draft. The existing version script counts drafts to prevent collisions. Failed drafts remain available for diagnosis. Full regression does not hold this lock. Workflow or documentation changes alone do not publish a DEV.

Seven-target builds run in Release. The separate compile matrix is manual. CLI tests run once through the existing coverage command; other workspace tests run separately. musl builds reuse the existing cache. macOS reuses the model cache while still checking model files and performing real inference.

Historical upgrades on seven targets, full CLI regression on three systems, and DEV API regression run independently. They verify source, version, and digests of the original build artifacts without compiling again. They do not block DEV publication. Report failures; do not declare a DEV fully validated until these checks succeed.

Stable publication waits for successful historical upgrades on all seven targets, all three system regressions, and API regression. Failed, cancelled, skipped, or missing results block publication. The upgrade script discovers every stable release from 1.0.6 onward. There is no stable 1.0.6 artifact, so the actual historical DEV baseline is also retained. Each new stable release automatically joins future upgrade validation.

Manual Release validation runs all native upgrade checks by default. After DEV publication, verify the public install, exact platform package versions, runtime status, and actual regressions for the related issues. Never count unexecuted checks as passed.

When a DEV must pass full acceptance before publication, merge with `[manual-release]` in the commit message to suppress automatic Release allocation while keeping push CLI CI enabled. Then dispatch Release for the exact merged source with `publish=true`, `full_regression_before_publish=true` and the requested unpublished `dev_version`. Publication waits for all seven native upgrades, all three system regressions and API checks from that same run; builds and regressions are not repeated. The default fast DEV order is unchanged.

For an explicitly requested DEV number, manual Release accepts `dev_version` in `X.Y.Z-dev.N` format. Its base can differ from the source manifest, so a published `1.0.12` baseline can produce the requested `1.0.13-dev.N` artifacts. It must have no Git tag or published package on any of the eight npm packages. Only an empty, unpublished DEV draft can be resumed after its previous release run finishes; preserve the failed run and reports. Draft notes record their owner run, and an active owner blocks resumption. Legacy drafts without an owner marker require all other Release runs to finish first. The corrected source still passes the normal builds and regression gates. Omit the input for automatic allocation. Stable releases reject this input.
