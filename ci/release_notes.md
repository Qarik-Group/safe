# New Features

- Added `safe dhparam` for generating randomized DH params,
  and storing the PEM data in the secret backend.

# Improvements

- `safe crl-pem` and `safe ca-pem` now support a path argument,
  triggering `safe` to store the corresponding PEM data in the
  secret backend, at `path`.

# Bug Fixes

- `safe cert` no longer stomps on pre-existing values stored
  in the path at which the cert is being generated.
