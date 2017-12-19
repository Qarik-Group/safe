# Improvements

- `safe curl` now has a `--data-only` flag that will cause it to
  skip the HTTP headers, and just print the raw data.  Perfect for
  scripting!
- `safe curl` now defaults to using the HTTP `GET` method if the
  only argument given is the URL to retrieve, making it behave
  more like regular curl.
