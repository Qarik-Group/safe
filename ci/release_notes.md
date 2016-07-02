# Bug Fixes

- Tree facilities like `safe tree` and `safe export` now work with
  Vault 0.6.0+, while retaining backwards compatibility with prior
  versions.  Fixes #31

# Development Improvements

- We now have a regression test suite, that gets tested against
  several versions of Vault (look Ma, no mocks!)
