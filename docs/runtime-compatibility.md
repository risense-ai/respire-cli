# Runtime compatibility contract

## Version selection

Consumers resolve one exact Runtime version from a pinned compatibility
manifest. `latest` is never a compatibility source. A release is installable
only when runtime version, CLI version, Client2 version, protocol range,
required capabilities, target, asset names, and source binding all match.

## Wire protocol

`PROTOCOL_V` remains a hard gate. A mismatch fails with
`protocol_version_mismatch`. Consumers do not downgrade silently or fall back to
a CLI shim. Capability negotiation is allowed only inside the frozen range and
only for keys declared by both sides.

Stage 1 business callers must send top-level `scope` with the verified health
`account_id`, `instance_id`, and wire `generation`, including result queries.
A caller missing this contract is not a compatible business client. It must not
retry an unconfirmed write with a refreshed scope or fall back to a CLI shim.
`scope_required` and `scope_mismatch` preserve an explicit failure; neither
proves that a previously admitted operation did not commit.

## Channels

| Component | Setting | Stable rule |
| --- | --- | --- |
| Runtime | `runtimeChannel` | Reject prereleases. |
| CLI | `cliChannel` | Reject prereleases and use CLI releases. |
| Client2 | `clientChannel` | Controls only Client2. |

Changing one channel never changes another component implicitly. Dev to stable
occurs only when an exact compatible stable exists. Otherwise the active dev
combination remains active and is reported as dev.

## Legacy consumers

The old CLI consumers that treat `sha256` and `binary_sha256` as the same value
cannot install canonical schema 2 archives whose hashes differ. They keep only
their previously verified combinations until repaired. New consumers may support
schema 1 by mapping `sha256` to `archive_sha256` and `triple` to
`target_triple`.

Client2's legacy installer requires a naked
`rsrs-runtime-<triple>[.exe]` in addition to the archive and metadata. That
asset remains mandatory during the compatibility window. Removing it requires a
separate versioned compatibility decision.

## Platform matrix

All eight targets in `runtime-control-contract.md` are supported. Every target
requires the archive, metadata, naked legacy binary where applicable, and
integrity evidence. Missing platform evidence blocks candidate promotion.

## Migration admission: first preservation slice

Automatic selection and CLI materialization now stop before replacing an
unbound legacy installation. A different pinned version does not bypass
verification of the existing Runtime selection. Existing endpoint, registration,
session or database evidence is preserved even if the old executable disappeared.
Configured profile paths are inspected read-only; they never supply request scope.
A preferences-only fresh `client.json` does not establish a legacy owner.

A trusted Runtime archive does not establish the old host CLI's provenance.
Replacing different stable CLI bytes therefore remains deferred until an explicit
host-transition proof is implemented. The error is
`legacy_runtime_migration_required`, not an upgrade-success result. Explicit,
verified offline Runtime installation remains available, but it does not authorize
subsequent replacement of an unbound old host. Fresh autostart installation resolves
and verifies the managed Runtime before publishing its registration; a failed
resolution leaves no new registration or maintenance marker.

Start and restart check existing migration evidence before acquiring the takeover
lock, then check it again while holding the lock. A statically unbound legacy
installation is rejected without creating takeover metadata. If admission passes
but evidence changes before the locked check, rejection may leave the newly
acquired coordination lock. Never delete that lock as rejection cleanup: another
controller may already depend on its identity. These checks do not make migration
atomic against writers outside the existing locks, including direct stable-image
copies; concurrent replacement and full rollback remain separate acceptance work.

This first slice does **not** implement an old-protocol adapter. It can also defer
otherwise legitimate split-CLI upgrades whose prior host lineage is unavailable.
Autostart requires a verified managed Runtime; portable or explicit Runtime images
without retained release proof must be installed deliberately before registration.
These limits must be resolved before calling the complete migration supported.
Do not remove authentication, infer account/generation, fake old health/version,
or silently switch old Client2's direct HTTP calls to the new contract.

### Reproducible Linux preservation checks

The official GNU CLI v1.0.20 fixture has SHA-256
`c03c131c61819a5f4d132cfe328f7c1da82c2f0b21a9c87d2b8870d1541a4c3e` and source
`26ead1ecf5c1a41e6d5e518aeb375e896f6c4c9e`. Obtain the binary and metadata from
[the formal release](https://github.com/risense-ai/respire-cli/releases/tag/v1.0.20)
and verify their exact digest before running:

```sh
RSRS_CORE_TEST_MODE=1 cargo test --locked -p respire --bin rsrs runtime_fetch
RSRS_TEST_LEGACY_CLI_BIN=/absolute/rsrs-v1.0.20 cargo test --locked -p respire \
  --bin rsrs automatic_install_preserves_official_cli_1_0_20 -- --ignored
python scripts/test-legacy-runtime-preservation.py \
  --legacy-binary /absolute/rsrs-v1.0.20 --candidate /absolute/new-rsrs \
  --report /absolute/preservation-report.json
```

The native script starts only its isolated legacy child, checks install/update/
start/restart/autostart deferral, then verifies the original PID, binary digest,
endpoint, selection and registration/maintenance/takeover absence, and queries
status with the actual old CLI. It separately checks that start/restart rejection
leaves a stopped, session-only installation unchanged. Cleanup terminates only
that child. Fresh-install unit tests cover download admission and a synthetic
verified Runtime plus mocked service manager with `enable(false)`; they do not
prove a complete real download, service-manager registration or `--now` startup.
The script does not download fixtures, touch an existing installation, prove new
wire compatibility, test Client2 desktop behavior, or establish real model/
platform/G1 acceptance.
