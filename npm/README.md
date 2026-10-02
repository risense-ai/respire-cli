# @rsrsai/cli

The launcher selects the platform binary package and forwards arguments to `rsrs`. Packages include the executable, runtime libraries and notices.

```sh
npm i -g @rsrsai/cli
# Or: pnpm add -g @rsrsai/cli
rsrs doctor
rsrs --help
```

| Platform | Package |
| --- | --- |
| Linux x64, musl (default) | `@rsrsai/linux-x64` |
| Linux arm64, musl (default) | `@rsrsai/linux-arm64` |
| Linux x64, glibc | `@rsrsai/linux-x64-gnu` |
| Linux arm64, glibc | `@rsrsai/linux-arm64-gnu` |
| Apple Silicon | `@rsrsai/macos-arm64` |
| Windows x64 | `@rsrsai/win-x64` |
| Windows arm64 | `@rsrsai/win-arm64` |

`artifact-manifest.json` defines targets and names. Intel Mac is unsupported.
Linux keeps the static musl package as its default. On a glibc distribution,
select the GNU build explicitly; the same choice applies to npm and pnpm:

```sh
RSRS_LIBC=glibc rsrs doctor
RSRS_LIBC=musl rsrs doctor
# Persist the selection for this shell:
export RSRS_LIBC=glibc
```

The glibc packages require a compatible glibc host; they do not run on Alpine.
If optional packages were omitted during installation, install the selected
platform package at the same version as `@rsrsai/cli`.
See [CLI source](https://github.com/risense-ai/respire-cli) for builds and runtime guides.

| Boundary | Behavior |
| --- | --- |
| Models | Separately installed with upstream licenses and source records |
| Runtime | Host manages lifecycle; sandbox uses authenticated client requests |
| Sync | Host-side login; encrypted server storage |
| Core binary | Separate license from the MIT launcher/binding |
