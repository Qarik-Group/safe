## New Features

- `safe` now writes a small `~/.svtoken` file for other
  applications (like [Spruce][1]) to use without having to
  understand the `~/.saferc` file format.
- `safe` now understands the `vault` subcommand, allowing users to
  hook up targets in `~/.saferc` to the `vault` cli.

# Bug Fixes
- `safe` no longer requires the `~/.vault-token` file to be set.
- `safe` now correctly uses the tokens listed in `~/.saferc` when
  connecting to the targeted vault.
