# Existing command checks

Current parser behavior and `rsrs --help` define the command contract.

| Scenario | Command |
| --- | --- |
| Version | `--version`, `-v`, `v`; JSON command `version` |
| Plugins | `plugin list`; `plugin test <EVENT> --payload <JSON>` |
| Causal chain | `chain <ID> --depth <N>` |
| Importance | `--importance important|trivial` |
| Isolated data | `ONEMEMORY_DATA_DIR=<path>` |
| Split | `split <ID>` preview; `split <ID> --go --spec <JSON>` apply |
| Tree maintenance | `tree-cure` report; explicit `--id` and `--parent` apply |

Plugins use the platform shell and do not inherit account-key variables. Explicit and
background sync share one persistent outbox. Foreground mutations wait for local
storage; the runtime performs network synchronization in the background. Explicit
`sync` waits for its captured queue boundary. Timing reports
must describe version, mode, sample and network conditions.

| Check | Scope |
| --- | --- |
| Existing tests | Commands, encryption, storage, sync, runtime and MCP contracts |
| `scripts/dev-release-sweep.ps1` | CLI contracts on Linux, macOS and Windows |
| `scripts/dev-api-smoke.py` | Positive and negative contracts for all 61 cloud routes |
| `scripts/dev-local-api-smoke.py` | All 72 local web actions on an ephemeral Linux runner |
| `scripts/dev-outbox-smoke.py` | Delayed network writes, independent decryption, finite sync, reset and retry |
| AI and legacy-vault supplements | Real CPU inference, deterministic provider contracts, injection and v1/v2/v3 recovery |
| `scripts/dev-smoke-gate.py` | Exact artifact identity, required observations and confirmed account cleanup |
| SDK | Exact target, Rust, ABI and file hashes |

Runtime checks must not bypass sandbox confinement. Release sweeps must not use real
user libraries or the production server.

Release smoke uses only `https://dev.rsrs.rs`. The manual `Dev server sweep` requires
the original successful build run and its exact source SHA; it never selects a
floating npm version. Reports contain no session files, credentials or raw payloads.

Main pushes publish a development version and stable tags publish a formal version
only after build, API and CLI gates pass. Interactive UI, real GPU/NPU hardware and
paid provider quality require separate validation; a deterministic provider fixture
does not measure model quality.
