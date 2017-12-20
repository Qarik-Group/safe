# Improvements

- `safe curl` now has a `--data-only` flag that will cause it to
  skip the HTTP headers, and just print the raw data.  Perfect for
  scripting!
- `safe curl` now defaults to using the HTTP `GET` method if the
  only argument given is the URL to retrieve, making it behave
  more like regular curl.

# Bug Fixes

- `safe rm -rf` now properly recurses through trees.  This
  behavior was a victim of the ANSI bug that we "fixed" in 0.5.0,
  and it lacked a comprehensive test in the regression suite.
  Both of these issues have been fixed.

# Notices

- We no longer test safe against version 0.6.4 of safe, since the
  [safe-boshrelease][1] has upgraded to 0.9.0; it may still work
  fine with 0.6.4, but we can offer no guarantee.  Update!


[1]: https://github.com/cloudfoundry-community/safe-boshrelease
