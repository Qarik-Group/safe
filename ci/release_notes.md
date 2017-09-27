## Improvements

- Fix a formatting issue with the output of `safe x509 show`
  where ANSI color code formatting was not properly applied.
- Targets with trailing slash(es) are stripped before being
  used, to avoid spurious 404's on write operations.
