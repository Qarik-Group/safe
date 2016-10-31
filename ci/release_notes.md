## New Features

- `safe tree` now takes an optional `-d` argument, which works
  like that of the traditional filesystem `tree` utility and only
  prints details for directory structures (not leaf nodes)
  Fixes #48
- `safe cert` now includes a `combined` attribute that contains
  both the certificate and the key, in a single value, for when
  you need that.
- New `safe pki init` command will set up your PKI backend
  configuration, if you'll take the time to answer a few simple
  questions.  README updated accordingly.
- Commands that need the `pki/` backend mounted now check if it is
  mounted, and provide a hint to go run `safe pki init`

## Bug Fixes

- `safe ca-pem` no longer prints out duplicate PEM files.
- `safe ca-pem` no longer prints out duplicate PEM files ;)
