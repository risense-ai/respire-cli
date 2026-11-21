# Shared host frontend

[Component boundaries](component-boundaries.md) records the ownership rules
and the integration work reviewed against its dated baseline.

The `respire` library owns the CLI frontend and the `rsrs` executable is its
entry point. Runtime provides business RPC. The hosts keep their command and
desktop entry points and use the supported RPC methods for business operations.

`crates/host-control` contains the shared account/key maintenance coordinator.
CLI and Client2 own native credentials, installation, component management and
Runtime startup/supervision. They deliver keys to the verified Runtime owner.
Runtime retains login, sync, database and memory operations through RPC.

Components communicate through the shared protocol and required capabilities;
they do not require matching version numbers, source commits or SDK versions.
Each component validates its own assets. No unknown account or key operation is
replayed to make an upgrade succeed.

Use historical stacks to prepare databases for migration tests. Verify old
hosts against a live Runtime in separate online interoperability tests.
For each component release, keep the other components fixed during the
upgrade test and verify the resulting protocol, ownership and data behavior.
