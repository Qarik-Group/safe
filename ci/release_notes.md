## New Features

- `safe fmt` picked up some new formats: `bcrypt` for
  Blowfish-based bcrypt (best for password storage), `crypt-md5`
  for legacy systems that need MD5 hashes, and `crypt-sha256` for
  a middle-ground between MD5 and SHA-512.

- `safe x509 show` will now print out a human-readable summary of
  a given certificate, to assist operators in exploring the Vault
  and verifying certificates stored therein.

## Improvements

- The pki-backend commands in safe have now been officially
  deprecated.  The new `safe x509` backend has been working out
  beautifully and is far easier to configure than the Vault PKI
  backend with its peculiar terminology.  Specifically, the
  following commands no longer exist: **pki init**, **ca-pem**,
  **crl-pem**, **cert**, and **revoke**.
