# Linux builds

CLI-side builds link a validated binary Core SDK. They do not compile Core
or ONNX Runtime sources.

| Item | Contract |
| --- | --- |
| Linux x64, glibc | `x86_64-unknown-linux-gnu` |
| Linux arm64, glibc | `aarch64-unknown-linux-gnu` |
| Linux x64, static musl | `x86_64-unknown-linux-musl` |
| Linux arm64, static musl | `aarch64-unknown-linux-musl` |
| musl container | `rust:1.95.0-alpine3.23`, same CPU architecture |
| SDK | Pinned binary SDK for the exact target |
| Output | `target/ci/<target>/release/rsrs` and staged notices |
| musl verification | No ELF `INTERP`/`NEEDED`; version checks on Ubuntu and Alpine |

On a glibc Linux host, prepare the SDK and compile the native GNU target:

```sh
target="$(uname -m)-unknown-linux-gnu"
node scripts/fetch-core-sdk.mjs "$target"
export RSRS_CORE_SDK_DIR="$PWD/.sdk/$target"
cargo build --release --locked -p respire --bin rsrs --target "$target" --target-dir target/ci
node scripts/stage-core-runtime.mjs "target/ci/$target/release"
```

The GNU build requires compatible glibc and the staged shared libraries. Choose
musl for a static libc build; neither architecture can be substituted for the other.
The npm launcher keeps musl as its default. Set `RSRS_LIBC=glibc` to select a GNU
platform package; see [npm platform selection](../npm/README.md).

For musl, use the existing Alpine container build:

```sh
bash scripts/build-linux-musl.sh "$(uname -m)-unknown-linux-musl"
```

The container fetches the SDK, compiles CLI/application crates and stages runtime/third-party
notices. Configure the SDK URL first. Caches stay in `target/musl-cache/<target>`.
Static libc does not establish support for every kernel, CPU or sandbox. Host
permissions still govern Linux keyring access.
