# Bug Fixes

- Fixes a regression introduced in 0.5.0 with the Spruce
  integration via `~/.svtoken`.  Safe was writing the wrong key
  value for the Vault address, because I tried to be more
  effficient and didn't notice that it was coming out "url".
  Oops.

# Improvements

- `safe` is now built against Go 1.9, which should properly plumb
  in support for macOS system certificate pools.  All you crazy
  kids with your in-house CAs trusted by your hip macbooks should
  have a better time of using safe without `-k`!

- The test suite is now run against 0.9.0, but not against 0.8.0
  (we still test against 0.8.3, the latest in the 0.8.x series)
