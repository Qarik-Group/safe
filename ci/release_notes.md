# Improvements

- Updated `safe cert` to default to the `default` role created by `safe pki init`
- Simplified `safe cert` so that you **must** specify the CN for the cert via `--cn`.
  Previously it auto-determined the CN based off of the PATH specified, which was confusing.

# Bug Fixes

- Removed extraneous messaging when `safe` iterates over mounted backends
