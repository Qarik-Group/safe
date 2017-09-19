# Bug Fixes

- Resolves an issue where `safe` on Darwin would fail to pull the root CAs
  properly, and was unable to find custom CAs. This does not appear to affect
  the Linux version.
