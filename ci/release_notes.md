# New Features

- `safe set` can now take arguments in the form `attr@/path`, to
  read the contents of an on-disk file into the named attribute of
  the path being modified.  This should allow importing multiline
  data (like RSA keys and SSL/TLS certificates) more naturally.
  Fixes #17

# Bug Fixes

- `safe rsa` now generates the RSA public key in PKCS#8 format,
  instead of PKCS#1 format.  Primary difference is that #8 uses
  the leader / trailer -- BEGIN/END PUBLIC KEY --, whereas #1 uses
  -- BEGIN/END RSA PUBLIC KEY --.  That extra "RSA" trips up some
  software that does explicit header inspection (ike CF UAA)
