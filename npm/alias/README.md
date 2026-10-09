# Short npm entry

`rsrs-cli` is a small install entry for the matching `@rsrsai/cli` version.
It forwards arguments and the process exit code through the existing launcher.
The scoped CLI continues to select and verify the native platform package.

Build with `node npm/scripts/pack-alias.mjs`. The resulting package is under
`npm/dist/rsrs-cli`. Publish only after `@rsrsai/cli` at the exact dependency version
is publicly available. Use `dev` for a development version and `latest` for a
formal version. Publishing this package requires its own npm authorization;
the scoped package's trusted publisher does not automatically authorize it.

After the initial publication, configure `risense-ai/respire-cli` with workflow
`npm-alias.yml` as this package's trusted publisher. Dispatch **Publish short
npm entry** to publish future formal versions after the scoped CLI is public.
Alias-only changes do not trigger the seven-platform native release workflow.

The user install command, once published, is `npm install -g rsrs-cli`.
Existing users can continue to use `npm install -g @rsrsai/cli`.
To change the install entry, first uninstall the previously installed npm
package to avoid both packages claiming the same global `rsrs` command.
This does not remove account data or model files.
