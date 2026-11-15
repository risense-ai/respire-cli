# Shared host frontend

The `respire` library owns the CLI frontend and the `rsrs` executable is its
entry point. The pure Runtime does not embed this frontend or preserve historical
Client2 host commands. Upgrade Client2 and CLI for the new Runtime generation.

`crates/host-control` contains the shared account/key maintenance coordinator.
CLI and Client2 own native credentials, installation, component management and
Runtime startup/supervision. They deliver keys to the verified Runtime owner.
Runtime retains login, sync, database and memory operations through RPC.

Components communicate through the shared protocol and required capabilities;
they do not require matching version numbers, source commits or SDK versions.
Each component validates its own assets. No unknown account or key operation is
replayed to make an upgrade succeed.

Historical stacks prepare data for database-upgrade regression, rather than
running old host commands against the new Runtime. Release Runtime first, then
update the CLI download default and supported minimum to that generation and
publish CLI and Client2. Previous releases and tags are retained. Focused local
tests do not replace native new-stack and database-upgrade acceptance.
