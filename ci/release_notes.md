# Changes to Defaults

To comply with the expectations of Mac OS Catalina
about x509 certificates, some changes have been made to
some of the default flag values for `x509 issue`.

* The default TTL for non-CA's is now 2 years instead of 10 years.
* All certificates now have the default extended key usages of `server_auth` and `client_auth`. Previously, the default was to have no extended key usages. These defaults can be overridden by providing any key usages manually.
* For CA certificates, the `key_cert_sign` and `crl_sign` key usages are provided by default. These defaults can be overridden by provided any key usages manually.

# New Features

* Due to the fact that not specifying key usages to `x509 issue` will cause the default key usages and extended key usages to be used, the key usage spec `no` was added to allow the user to specify that they want no key usages on the certificate at all.

# Improvements

* Key usage strings provided on the command line are now case-insensitive.