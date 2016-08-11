# New Features

- Added `safe curl` command for arbitrarily executing HTTP queries
  against a safe target. This allows you to authenticate to Vault,
  and hit the raw APIs for experimentation.

- Added `safe cert` command for issuing signed certificates using
  Vault's PKI backend.

- Added `safe revoke` command for revoking certificates issued
  using Vault's PKI backend.

- Added `safe crl-pem` command for displaying the Certificate
  Revocation List (CRL) in PEM format, pulled from Vault's
  PKI backend.

- Added `safe ca-pem` command for displaying the Certificate
  Authority certificiate in PEM format, pulled from Vault's PKI
  backend.
