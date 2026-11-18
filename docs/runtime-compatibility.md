# Runtime compatibility contract

## Version selection

Components match through the wire protocol and required capabilities, not equal
product versions, SDK versions or source commits. The upgraded CLI obtains the
current supported Runtime through its published download pin. Resolve and verify
that release's target, assets and integrity before installation; a `latest`
label alone does not prove compatibility. Candidate hashes identify tested
artifacts and do not bind independently released components in production.

Upgrade regression prepares data with each supported historical stack, upgrades
the components, then verifies database migration, integrity and memory operations
with the new compatible stack. Include database-changing DEV checkpoints; omit
redundant DEV combinations with unchanged persistent formats. Running old clients
against the new Runtime is not an acceptance requirement.

Historical session and credential-operation journals are outside this upgrade
contract. In particular, an unfinished offline Super Key recovery created by an
older host may retain an empty login credential slot that the current host
rejects explicitly. Do not replay that unknown operation or delete its credential
slot to make an upgrade test pass; use a fresh isolated operation when verifying
the new host's recovery and registration flow. Database and original-key recovery
checks remain required.

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

The following describes historical installers and preservation checks. These
clients supply upgrade databases; their old Runtime interfaces are not a support
requirement for the coordinated DEV update.

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

## Migration admission

Automatic selection and CLI materialization stop before replacing an unbound
legacy process or startup registration. A different pinned version does not
bypass verification of the existing Runtime selection. Existing endpoint and
registration records still require an explicit handoff even if the old executable
disappeared. Configured profile paths are inspected read-only; they never supply
request scope. Existing session and database files do not block installation of
the new Runtime. Installation does not open the database, migrate it or authorize
an unlock; those operations still require the host key and Runtime admission.

Historical upgrade acceptance seeds both libraries with the historical binary,
ends its fixture-owned process, stages the upgraded CLI, then uses that CLI's real
default-pin download. No new Runtime is preinstalled before the historical data.
The report requires verified installed bytes, unchanged ciphertext, sync work and
session keys, and SQLite integrity checks before opening the upgraded libraries.
This proves the stopped-library upgrade and download path, not automatic takeover
of an old running process.

An old CLI executable at the managed path does not require a matching version
or known digest to proceed with installation. Admission still checks for an unsafe
path or an unbound process or startup record. The new Runtime payload is verified
before activation. Database compatibility is established when the new Runtime
opens the library with the original key. Fresh autostart installation verifies the
managed Runtime before publishing its registration.

Start and restart check existing migration evidence before acquiring the takeover
lock, then check it again while holding the lock. A statically unbound legacy
installation is rejected without creating takeover metadata. If admission passes
but evidence changes before the locked check, rejection may leave the newly
acquired coordination lock. Never delete that lock as rejection cleanup: another
controller may already depend on its identity. These checks do not make migration
atomic against writers outside the existing locks, including direct stable-image
copies; concurrent replacement and full rollback remain separate acceptance work.

Autostart requires a verified managed Runtime; portable or explicit Runtime images
without retained release proof must be installed deliberately before registration.
Do not remove authentication, infer account/generation, fake old health/version,
or silently switch old Client2's direct HTTP calls to the new contract.

### Reproducible Linux preservation checks

The official GNU CLI v1.0.20 fixture has SHA-256
`c03c131c61819a5f4d132cfe328f7c1da82c2f0b21a9c87d2b8870d1541a4c3e` and source
`26ead1ecf5c1a41e6d5e518aeb375e896f6c4c9e`. Obtain the binary and metadata from
[the formal release](https://github.com/risense-ai/respire-cli/releases/tag/v1.0.20)
and verify their exact digest before running:

```sh
RSRS_CORE_TEST_MODE=1 cargo test --locked -p respire --lib runtime_fetch
RSRS_TEST_LEGACY_CLI_BIN=/absolute/rsrs-v1.0.20 cargo test --locked -p respire \
  --lib automatic_install_admits_official_cli_1_0_20 -- --ignored
python scripts/test-legacy-runtime-preservation.py \
  --legacy-binary /absolute/rsrs-v1.0.20 --candidate /absolute/new-rsrs \
  --report /absolute/preservation-report.json
```

The native script starts only its isolated legacy child, checks install/update/
start/restart/autostart deferral, then verifies the original PID, binary digest,
endpoint, selection and registration/maintenance/takeover absence, and queries
status with the actual old CLI. It separately checks that a stopped, session-only
installation reaches the download boundary without changing the old session;
the source-test switch deliberately disables the actual download. Cleanup terminates only
that child. Fresh-install unit tests cover download admission and a synthetic
verified Runtime plus mocked service manager with `enable(false)`; they do not
prove a complete real download, service-manager registration or `--now` startup.
The script does not download fixtures, touch an existing installation, prove new
wire compatibility, test Client2 desktop behavior, or establish real model/
platform/G1 acceptance.
