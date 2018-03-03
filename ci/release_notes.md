# Bug Fixes

- Paths given to `safe curl` are now canonicalized, to remove
  extra slashes, since Vault just won't tolerate those sorts of
  shenanigans.
