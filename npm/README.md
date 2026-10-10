# rsrs-cli

The launcher selects the platform binary package and forwards arguments to `rsrs`. Packages include the executable, runtime libraries and notices.

```sh
npm i -g rsrs-cli
# Or: pnpm add -g rsrs-cli
# DEV: npm i -g rsrs-cli@dev
rsrs doctor
rsrs --help
```

`rsrs-cli` is the primary install entry. It depends on the exact same version of
`@rsrsai/cli`, which selects the native platform package. Stable releases use
`latest`; development releases use `dev`.

| Platform | Package |
| --- | --- |
| Linux x64, musl (default) | `@rsrsai/linux-x64` |
| Linux x64, glibc | `@rsrsai/linux-x64-gnu` |
| Apple Silicon | `@rsrsai/macos-arm64` |
| Windows x64 | `@rsrsai/win-x64` |

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
| Core binary | Separately licensed proprietary binary and public binding |

## License

First-party material uses the [Respire Noncommercial License 1.0](https://github.com/risense-ai/respire-cli/blob/main/LICENSE).
Personal noncommercial use and self-hosting are permitted. Commercial use,
including internal business deployment, requires prior written authorization.
See [commercial licensing](https://github.com/risense-ai/respire-cli/blob/main/COMMERCIAL-LICENSE.md).
