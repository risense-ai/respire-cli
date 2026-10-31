# Automatic releases

Push an unused release tag pointing to a reviewed commit on `main`:

```sh
git tag v1.0.17-dev.16 <reviewed-main-commit>
git push origin v1.0.17-dev.16
# Stable uses the same automatic workflow, for example v1.0.17.
```

DEV tags determine the binary and npm version; CI prepares matching ephemeral
Cargo, lockfile and npm versions. Stable tags require the CLI source version,
Cargo.lock and npm manifest to match first, including the protocol publication
gate. Run `node npm/scripts/set-build-version.mjs X.Y.Z`, commit those three
files to `main`, then push `vX.Y.Z`. DEV tags publish `dev`; stable tags publish
`latest`.
Ordinary `main` pushes run source CI and warm dependency caches without
allocating a release. Manual dispatch remains available for preparation/recovery.

Both tag forms automatically run source CI, seven native builds, package/hash
and architecture checks, real inference, all applicable historical upgrades,
cloud/API checks and account migration. Publication waits for the full gate.
The matching short npm entry is dispatched automatically. A completed Release
automatically starts read-only public package and isolated-install verification.
Tag CI has its own concurrency group, so a later `main` push cannot cancel it.

## Acceptance performance

Source CI retains the pinned SDK and Rust dependency caches. Release acceptance
keeps every case and its existing deadlines and cleanup, with these changes:

- The sweep writes progress reports at most once every five seconds. Failures
  and completion force an immediate complete report. CLI calls and assertions
  still execute in order. A local 900-row benchmark retained identical report
  contents and reduced twelve report calls from 8.8 seconds to 0.6 seconds;
  this measures report overhead, not total release duration.
- Historical versions run two at a time. Each has its own profiles, runtime
  port, extracted binary and report; verified model inputs are read-only.
- Independent Linux supplements run two at a time. Login interruption still
  waits for the outbox fixture that prepares its model. The combined gate still
  requires every suite to pass.

Real model downloads, inference, historical upgrades and hosted-runner queue
time remain part of acceptance. The workflow does not reuse a previous version's
runtime result as proof for a new candidate.

The approved DEV API is `https://api-dev.rsrs.rs`. Its exact source revision
remains pinned in `scripts/dev-api-coverage.json` and the repository variable.
Cloudflare BIC is disabled only for that API hostname. For deliberate GitHub
provider failures, the transport suite accepts either the origin's fixed error
or Cloudflare's exact structured 502 response. It still rejects credentials in
the response and requires the consumed state to reject replay with HTTP 400.
