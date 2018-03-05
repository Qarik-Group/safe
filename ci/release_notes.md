# Improvements

- X.509 certificates can now be issued with Key-Usage and Extended
  Key-Usage constraints.  See RFC 5280 for details.

- `safe x509 show` now prints out human-readable (and comprehensible!)
  explanations for Key-Usage and Extended Key-Usage constraints.

# Bug Fixes

- Paths given to `safe curl` are now canonicalized, to remove
  extra slashes, since Vault just won't tolerate those sorts of
  shenanigans.
