# Bug Fixes

 - Fix `versions` command description

# New Features

- `safe envvars` - New command that displays available environment variables for use with `safe`

- Auto-mount `secret` on `safe init` and `safe local` - In more recent
  versions of Vault, `secret` is not mounted by default. Safe will ensure that
  the mount is created anyway unless the `--no-mount` option is given. The flag
  will not unmount an existing `secret` mount in versions of Vault which mount
  `secret` by default.

- `safe auth approle` - Added the ability to auth via [AppRole](https://www.vaultproject.io/docs/auth/approle.html)