# Linux builds

The CLI frontend builds without a Core SDK, native model libraries or a Runtime
binary. Business commands connect to a separately installed Runtime.

| Item | Contract |
| --- | --- |
| Linux x64, glibc | `x86_64-unknown-linux-gnu` |
| Linux x64, static musl | `x86_64-unknown-linux-musl` |
| Linux ARM64, glibc | `aarch64-unknown-linux-gnu`, native `ubuntu-24.04-arm` |
| Linux ARM64, static musl | `aarch64-unknown-linux-musl`, native `ubuntu-24.04-arm` |
| musl container | `rust:1.95.0-alpine3.23`, same CPU architecture |
| SDK | Not needed for the CLI frontend |
| Output | `target/ci/<target>/release/rsrs` |
| musl verification | No ELF `INTERP`/`NEEDED`; version checks on Ubuntu and Alpine |

CLI 2.0.0-dev.3 deferred Linux ARM64 musl under [issue #272](https://github.com/risense-ai/respire-cli/issues/272).
The dev.4 configuration restores its build and acceptance gates; publication
still requires the startup, inference and owned-cleanup checks to pass.

On a glibc Linux host, use the pinned Rust toolchain to build the native GNU target:

```sh
target="$(uname -m)-unknown-linux-gnu"
cargo build --release --locked -p respire --bin rsrs --target "$target" --target-dir target/ci
```

The GNU frontend requires compatible glibc. Choose
musl for a static libc build; neither architecture can be substituted for the other.
The npm launcher keeps musl as its default. Set `RSRS_LIBC=glibc` to select a GNU
platform package; see [npm platform selection](../npm/README.md).

For musl, use the existing Alpine container build:

```sh
bash scripts/build-linux-musl.sh "$(uname -m)-unknown-linux-musl"
```

The container compiles the CLI frontend without downloading a Core SDK or staging
model runtime libraries. Caches stay in `target/musl-cache/<target>`.
Static libc does not establish support for every kernel, CPU or sandbox. Host
permissions still govern Linux keyring access.

Linux ARM64 builds and acceptance require `uname -m=aarch64` on a native Linux
runner. No QEMU or cross build substitutes for model/runtime acceptance. GNU
artifacts require an AArch64 ELF with its interpreter and resolved dynamic
runtime dependencies. Musl artifacts require no ELF interpreter or shared
library imports and also run in native ARM Alpine.
Runtime builds and explicit joint-workspace validation still require the pinned
Core SDK for the exact target and its native libraries. SDK download credentials
belong only to those workflows, not the frontend build above. Install the verified
Runtime separately with `rsrs runtime install` before running business commands.

The separate Alpine inference probe uses the already prepared model files, a separate
owned profile and no container network or forwarded credentials. It executes
actual CPU model inference as well as the native executable startup check.

Historical upgrades keep every actual ARM source. Only `v1.0.15`, `v1.0.16` and
`v1.0.17-dev.12` have an explicit ARM distribution gap. Their complete absence
is reported as not applicable; partial assets or any other missing version
still fail. Existing ARM releases, including the 1.0.6 DEV baseline and 1.0.10
compatibility draft, remain strict upgrade sources.
