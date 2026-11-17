# Database upgrade checkpoints

This registry records source and release-inventory checks on 2026-11-17. It is
not a receipt for a successful native upgrade. The existing upgrade harness now
selects and seeds these inputs, but native execution remains required before
publishing a candidate that claims this coverage.

`scripts/published_upgrade_policy.py` selects the two DEV inputs below in both
profiles. The full profile also keeps historical formal releases; the critical
profile keeps the latest applicable formal release. These are database inputs,
not requirements to support old hosts with the new Runtime.

| Published tag | Verified source SHA (`cli-build-x86_64-unknown-linux-gnu.json`: `git_sha`) | Required distinct input |
| --- | --- | --- |
| `v1.0.11-dev.1` | `309d7a2925d2d241996f6c0e324c88b3a040ca81` | Unmarked legacy encrypted payloads containing `supersedes`, `superseded_by`, and `see_also` |
| `v1.0.17-dev.6` | `d5001f8ca88abbcf3f1b99df914c6689b6360272` | Populated query attribution and witness state, alongside encrypted memories and pending synchronization work |

The published manifests agree with the local tag commits. Release inventories:
[dev.1](https://github.com/risense-ai/respire-cli/releases/tag/v1.0.11-dev.1),
[dev.6](https://github.com/risense-ai/respire-cli/releases/tag/v1.0.17-dev.6).
At each source, inspect `crates/crypto/src/engine.rs` and
`crates/storage/src/transport/local.rs`. The dev.1 writer seals relationship
fields with the legacy data key and no `rsrs:v1:` envelope marker. Formal
`v1.0.11` (`ca071482e37028273de374863e264ef25ced786f`, manifest verified)
already has the explicit namespace writer in `crates/crypto/src/{crypto,engine}.rs`;
its fresh database therefore does not replace a populated pre-namespace input.
The dev.6 migration adds `query_log.request_id`, `idx_query_request`, and
`query_feedback`; `local/witness_schema.sql` installs `witness_log` and source
triggers. These are persistent database changes, not host credentials or model
index files. Later formal schemas can contain these objects without proving
that a populated older database upgrades correctly.

## Formal equivalence and exclusions

`v1.0.15-dev.10` (`4549184ecdd7520b623a5c091a4f75d608a2d467`) and formal
`v1.0.15` (`82e41ed1edfdeffc6a9d74e28dedc61c85d9f862`) have verified published
manifest SHAs and identical `local.rs`, `local/revision.rs`,
`local/revision_schema.sql`, and `local/sync_schema.sql` under
`crates/storage/src/transport/`. In particular, the same memory revision
insert/update/delete triggers and meta token are installed. The formal source
already represents that format in full coverage, so dev.10 is no longer a
separate DEV checkpoint. Existing exact asset gaps for that tag remain recorded.
The earlier `v1.0.6-dev.37075716045` equivalence to formal `v1.0.7` is documented
with manifest source SHAs in [Runtime upgrade sources](runtime.md#upgrade-regression-sources).
Model-derived indexes and host credential/keyring changes alone do not add DEV
database inputs. Ordinary DEV revisions do not each require a checkpoint.

## Assets and required seeds

Each supported target requires all three release assets: the CLI executable,
`rsrs-<target>-runtime.tar.gz`, and `cli-build-<target>.json`. The live inventories
were checked against all eight targets without downloading native packages:

| Tag | Complete targets | Entirely absent targets |
| --- | --- | --- |
| `v1.0.11-dev.1` | Windows x64/ARM64; Linux x64/ARM64 GNU/musl; macOS ARM64 | macOS x64 |
| `v1.0.17-dev.6` | Windows x64; Linux x64 GNU/musl; macOS ARM64 | Windows ARM64; Linux ARM64 GNU/musl; macOS x64 |

Intel macOS uses the existing pre-1.0.20 rule. Only dev.6 is added to the exact
Linux/Windows ARM gap sets. A partially present trio must still fail, including
on a historically absent target; an unknown missing target must also fail.

Seed dev.1 through its historical encrypted relationship writer. Retain original
URK/key evidence and nonempty relationships in decryptable memories. Seed dev.6
with nonempty query attribution/feedback and witness history through its source
operations. Empty tables or merely starting an old binary do not establish these
inputs. Both need original encrypted active/deleted records and outstanding sync
work. Verify the original keys decrypt the old records after migration, preserve
relationships and pending work, then verify new writes, reads, and synchronization.
Any retained experimental database state must be exercised explicitly rather
than inferred from an empty fresh schema. Credential migration remains a fixture
precondition, not evidence of database preservation.

The existing upgrade harness seeds and checks these special states in both
accounts. Historical seeds also create an encrypted tombstone through the old
CLI's `remember` and `forget` commands. Empty/decrypted tombstone payloads, missing
active records, and empty synchronization work fail before upgrade; the existing
decrypted library comparisons then preserve the deleted record, flags, and work.

This harness still uses offline synthetic identities. It checks pending work
preservation, not an actual post-upgrade synchronization exchange. Reports expose
`post_upgrade_sync_checked: false`; a successful harness report or `full_coverage`
(all selected source versions) does not prove complete upgrade acceptance.
Real synchronization needs account creation, remote readback, and cleanup; that
fixture is deferred rather than adding it to this bounded patch. Run 44098649710
predates these seeds and is only evidence for finding existing Runtime24 problems,
not a final candidate with complete database-upgrade coverage.

Registry/unit checks and source comparisons cannot substitute for real native
database-upgrade reports. The older dev.10 references
in `runtime.md` and `release-validation.md` describe the previous registry;
this document records the replacement set and its integration boundary.

## Release supplement: legacy ciphertext synchronization

The `legacy_vault` report filename and suite identifier remain stable, but the
default `dev-legacy-vault-smoke.py` release case is `legacy_ciphertext_sync`.
It registers a current disposable account, retains its original URK and current
vault, and encodes an active record and an encrypted tombstone in the historical
`onememory:data:v1` domain. The existing public migration must convert these
records without changing plaintext, deletion state or the original source.
The upgraded profile must push the converted records to the real DEV server;
an independent current device logs in through host RPC, pulls them, decrypts
the active record, and reads back its exact ciphertext. Before synchronization,
the migrated tombstone must still decrypt with the original URK. On the independent
device, both the received head and the local record must contain the same ID,
`deleted=true` and empty ciphertext/nonce, matching the current server's
content-free tombstone protocol. Missing deletion records fail. Both cloud
accounts and fixture-owned native credentials must be cleaned up.

The final release no longer runs the old v1/v2/v3 authentication combinations,
changes server authentication salts, or requires old session/credential locations
and fixed TTY prompt sequences. The old `--auth-salt-only` script option remains
an explicit manual diagnostic, outside the final gate; the focused workflow input
is now `database_sync_only`. Current login transaction, continuation, wrong-key,
identity and credential cleanup checks remain independent requirements. No failed
or unknown login is retried to obtain a passing result.

This supplement exercises genuine legacy encryption with synthetic records in
the current schema. It complements, and does not replace, the formal/DEV schema
checkpoints above. It does not change their `post_upgrade_sync_checked: false`
reports or claim that every historical schema has completed remote sync. A green
unit test or the presence of this fixture is not evidence that its real network
execution passed; acceptance requires the exact candidate's successful report.
