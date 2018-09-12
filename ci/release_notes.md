# Improvements

- `safe x509 renew` can now recover from missing CRLs and missing
  serial numbers, in case you've imported the certificate and
  private key from somewhere else.

- `safe x509 validate` now complains is a certificate is listed as
  a CA but does not have its serial number or CRL.
