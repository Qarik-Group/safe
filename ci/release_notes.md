# New Features

- Added `safe dhparam` for generating randomized DH params,
  and storing the PEM data in the secret backend.

- `safe get` can now be used to get a single key from a path,
  using the format `safe get secret/path/to/thing:key`. Similarly,
  this notation can be used for things like `safe export`, and
  `safe copy`.


# Improvements

- `safe crl-pem` and `safe ca-pem` now support a path argument,
  triggering `safe` to store the corresponding PEM data in the
  secret backend, at `path`.

# Bug Fixes

- `safe cert` no longer stomps on pre-existing values stored
  in the path at which the cert is being generated.
