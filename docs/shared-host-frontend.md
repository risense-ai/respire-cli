# Shared host frontend

The `respire` library now owns the existing CLI frontend. The `rsrs` executable
is a thin entry point. Runtime reuses the same Rust source to support unchanged
Client2 host commands and the original v1 stdio account interface.

`crates/host-control` contains the shared account/key maintenance coordinator.
Ordinary CLI behavior still uses the CLI lifecycle implementation; embedding
provides only the selected Runtime image verifier and lifecycle callbacks.
The embedding is process-local, not a client credential or a new protocol.

An embedded command cannot download, replace, clean or materialize the Runtime
or a stable CLI. It revalidates Client2's already selected image. Ordinary CLI
legacy-install preservation from PR #220 is retained. No unknown account or key
operation is replayed to make an upgrade succeed.

The Runtime integration consumes the same frontend and shared source. Keep both
consumers synchronized for changes to these files. Release Runtime first, then
update the CLI pin to the published Runtime and publish the new CLI dev version.
Previous Releases and tags are retained. Focused local tests do not replace the
native account and multi-platform CI acceptance gates.
