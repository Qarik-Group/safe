# New Features

- It is now possible to configure multiple PKI backends
  using the `--backend` flag to `safe pki init`, and reference
  those backends with the same flag using `safe cert`, `safe ca-pem`,
  and all your other familiar PKI-related `safe` commands.

  This is especially useful if you need to have a subset of certs only
  signed by a specific CA, like OpenVPN, and do not want all certs signed
  by that CA to be valid client certificates.
