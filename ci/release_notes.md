## Improvements

- The pki-backend commands in safe have now been officially
  deprecated.  The new `safe x509` backend has been working out
  beautifully and is far easier to configure than the Vault PKI
  backend with its peculiar terminology.  Specifically, the
  following commands no longer exist: **pki init**, **ca-pem**,
  **crl-pem**, **cert**, and **revoke**.
