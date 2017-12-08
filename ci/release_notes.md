# Improvements

- `safe renew all` now skips vaults you've never authenticated
  against (and therefore have no token worth renewing), and
  accumulates errors until the end.
