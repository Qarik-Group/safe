## New Features

- New `safe ls` command lets you list individual levels of the
  directory hierarchy.  Could be useful for some shell
  auto-completion.  Just sayin'

## Improvements

- Fix a formatting issue with the output of `safe x509 show`
  where ANSI color code formatting was not properly applied.
- Targets with trailing slash(es) are stripped before being
  used, to avoid spurious 404's on write operations.
