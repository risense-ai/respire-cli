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
background sync share coordination; network work may block or queue. Timing reports
must describe version, mode, sample and network conditions.

| Check | Scope |
| --- | --- |
| Existing tests | Commands, encryption, storage, sync, runtime and MCP contracts |
| `scripts/dev-release-sweep.ps1` | GitHub Actions only; isolated temporary dev accounts |
| Coverage | Existing measured modules; CI declares exclusions |
| SDK | Exact target, Rust, ABI and file hashes |

Runtime checks must not bypass sandbox confinement. Release sweeps must not use real
user libraries or the production server.
