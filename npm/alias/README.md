# Short npm entry

`rsrs` is a small install entry for the matching `@rsrsai/cli` version.
It forwards arguments and the process exit code through the existing launcher.
The scoped CLI continues to select and verify the native platform package.

Build with `node npm/scripts/pack-alias.mjs`. The resulting package is under
`npm/dist/rsrs`. Publish only after `@rsrsai/cli` at the exact dependency version
is publicly available. Use `dev` for a development version and `latest` for a
formal version. Publishing this package requires its own npm authorization;
the scoped package's trusted publisher does not automatically authorize it.

The user install command, once published, is `npm install -g rsrs`.
Existing users can continue to use `npm install -g @rsrsai/cli`.
To change the install entry, first uninstall the previously installed npm
package to avoid both packages claiming the same global `rsrs` command.
This does not remove account data or model files.
