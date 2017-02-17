# New Features

- Added support for `safe ask`. Similar to `safe set`, but with no confirmation,
  and user input is not obscured.
# Improvements

- `safe pki init` no longer prompts you for the default TTL/max TTL.
  It defaults to '10y', and allows you to override that via the `--ttl` flag.
- `safe pki init` configures the initial PKI role to allow cert generation
  for all CNs.

# Bug Fixes

- Removed extraneous messaging when `safe` iterates over mounted backends
