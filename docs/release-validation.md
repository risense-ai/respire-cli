# Release validation

DEV gates: exact-source workspace unit tests and existing coverage checks, one Release build for each of seven targets, native executable startup, real quantized CPU inference on macOS, pinned SDK digests, and consistent artifacts for all eight npm packages.

Only version allocation and publication share a serial lock. Allocation reserves the DEV number in an unpublished draft. The existing version script counts drafts to prevent collisions. Failed drafts remain available for diagnosis. Full regression does not hold this lock. Workflow or documentation changes alone do not publish a DEV.

Seven-target builds run in Release. The separate compile matrix is manual. CLI tests run once through the existing coverage command; other workspace tests run separately. musl builds reuse the existing cache. macOS reuses the model cache while still checking model files and performing real inference.

Historical upgrades on seven targets, full CLI regression on three systems, and DEV API regression run independently. They verify source, version, and digests of the original build artifacts without compiling again. They do not block DEV publication. Report failures; do not declare a DEV fully validated until these checks succeed.

Stable publication waits for successful historical upgrades on all seven targets, all three system regressions, and API regression. Failed, cancelled, skipped, or missing results block publication. The upgrade script discovers every stable release from 1.0.6 onward. There is no stable 1.0.6 artifact, so the actual historical DEV baseline is also retained. Each new stable release automatically joins future upgrade validation.

Manual Release validation runs all native upgrade checks by default. After DEV publication, verify the public install, exact platform package versions, runtime status, and actual regressions for the related issues. Never count unexecuted checks as passed.

For an explicitly requested DEV number, manual Release accepts `dev_version`. It must match the CLI manifest base and must have no Git tag or published package on any of the eight npm packages. Only an empty, unpublished DEV draft can be resumed after its previous release run finishes; preserve the failed run and reports. The corrected source still passes the normal builds and regression gates. Omit the input for automatic allocation. Stable releases reject this input.
