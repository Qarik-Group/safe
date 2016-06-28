# New Features

- `safe set` can now take arguments in the form `attr@/path`, to
  read the contents of an on-disk file into the named attribute of
  the path being modified.  This should allow importing multiline
  data (like RSA keys and SSL/TLS certificates) more naturally.
  Fixes #17
