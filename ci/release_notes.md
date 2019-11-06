# Improvements

* CA Certs configured with the `--ca-cert` flag to `target` are now
  exposed through the `.svtoken` file that Spruce uses to get Vault
  information. At the time of this writing, Spruce won't do anything with
  the CA Cert values, but now it has a means of doing so.

# Bug Fixes

* The VaultKV library was missing a couple error checks. These could lead
  to segfaults when attempting to read the response body. No longer. (#192)
* The VaultKV library was not reading to the end of the response body
  when making requests to /sys/health. Now it is, so those connections
  can be reclaimed for reuse. Safe doesn't usually make health checks
  en masse, so this isn't a huge deal, but it is a fixed bug nonetheless.
