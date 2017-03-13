# New Features

- `safe x509 issue` is a new command that lets you issue TLS/SSL
  certificates, with optional CA management.  It supports all
  three varieties of subject alternate names (IPs, emails and DNS
  names), RSA key strength selection (1024 / 2048 / 4096), custom
  certificate lifetimes, and allows creation of CA certificates
  to arbitrary depths.

- `safe x509 revoke` provides certificate revocation features,
  including painless Certificate Revocation List (CRL) management.

- `safe x509 validate` sports a wide array of checks and
  verifications you can run against a path in the Vault, making it
  easier to ensure that (for example) the certificate and private
  key actually go together, the certificate hasn't been revoked, the
  certificate hasn't expired, and so on.

- `safe x509 crl --renew  path/to/ca` will re-sign your CAs CRL,
  without affecting the list of revoked certificates.  Trust us,
  if you need this, you'll know it.

# Improvements

- A new command-line parser (`go-cli`) makes life easier for
  operators, and brings with it the potential to outfit existing
  commands with more flags.

# Bug Fixes

- `safe move`, `safe copy` and `safe delete` now no longer
  short-circuit long chains of sub-commands if they are recursive,
  not forced, and the operator says "no" at the confirm prompt.
  Instead, they only terminate the current sub-command,and resume
  execution with the next command in the chain.

- `safe` is now built as a static binary, so it can be used in things
  like alpine-linux with more success.
