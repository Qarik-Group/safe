# New Features

* `x509 renew` and `x509 reissue` now accept the `-n` and `-s` flags to update
subject alternative names and subjects respectively.
* `undelete` now treats not specifying a version to mean the latest version
(@daviddob)
* `cp` gives a proper error when trying to perform copy all versions of a
specific version of a secret, which doesn't make any sense. (@daviddob)

# Bug Fixes

* `x509 reissue` now properly reads in the key usage flags.
* `cp` will no longer panic when trying to copy a version of a secret which is
not the latest. (@daviddob)