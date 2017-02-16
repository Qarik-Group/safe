## Bug Fixes

- Fix an issue with the error handling from `safe unseal'

- Updated logic to check mounted backends to work with newer
  versions of Vault.

- Fix an issue whereby the first `safe -k target` would _not_
  honor the `-k` flag.  Now, `safe -k` works as expected, in all
  tested cases.
