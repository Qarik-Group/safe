# Improvements

- `safe x509 issue` no longer propagates duplicate `--name` values
  into the resulting X.509 certificate's subject alt names list.

# Bug Fixes

- If you somehow manage to create an empty path via `safe set` or
  some other out-of-band access to the Vault, `safe paths` will no
  longer panic when it encounters it.
