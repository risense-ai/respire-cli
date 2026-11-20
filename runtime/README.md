# Legacy `rsrs-runtime` helper

This workspace member records the original split-era helper and its wire
behavior. The product `rsrs-runtime` is built and released by the dedicated
[Runtime repository](https://github.com/risense-ai/respire-runtime). The CLI
and Client2 use the released Runtime and determine interoperability by the
wire protocol and the methods or capabilities they need.

## Build

```sh
cargo build -p respire_runtime
```

The binary is `target/debug/rsrs-runtime` (`publish = false`; released builds
are cut from the dedicated runtime repository, not this workspace).

## Run

```sh
rsrs-runtime serve [--host 127.0.0.1] [--port 15169] [--data-dir DIR] [--supervised]
rsrs-runtime --json runtime start     # same as serve, prints a start envelope
rsrs-runtime [--json] runtime stop    # or --stop: drain + stop the resident runtime
rsrs-runtime --status                 # health probe
rsrs-runtime --version
```

Unknown arguments exit with code 2. These invocation shapes describe this
helper's historical lifecycle contract. For current product lifecycle checks,
see [Runtime control contract](../docs/runtime-control-contract.md).

## Identity and health

The helper still emits the historical `runtime_compat` block alongside
`runtime_version` in its health identity. Keep that shape for historical
consumers. The window is not part of the current Runtime's release metadata
or the CLI's interoperability policy.

`RSRS_RUNTIME_BOOT_TOKEN` is consumed with `respire_spawn` semantics: read
once, then removed from the environment. Managed-boot verification (the
host-side registration/maintenance fence) remains host-managed through
`host_hooks` until the supervisor moves into this crate (P2).

## Status

This helper returns a stub for `assets.status`. Use the dedicated Runtime
release for current asset inventory and lifecycle behavior.
