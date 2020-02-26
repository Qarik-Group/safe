# Improvements

* `x509 renew` and `x509 reissue` now declare the new expiry time in a more
  human-readable format.
* Commands that talk to Vault that receive non-JSON responses should now give a
  more descriptive response. This could happen if you're targeting something
  that isn't Vault, or, say, if a load balancer that should have passed traffic
  through to Vault decided to respond as itself because of an error or
  misconfiguration.
* Communications to Strongbox are now traced when debugging is turned on.

# Bug Fixes

* You can no longer attempt to authenticate when you have no Vault targeted.
* `x509 show` and `x509 validate` used to fail if your certificate chain ended
  with something that wasn't a PEM block (such as whitespace). Now, this will
  not cause an error as long as one certificate was successfully found.
* `seal` and `unseal` would not add a default port (80 and 443) the same way
  that other commands did, which could cause connection refused errors for
  these specific commands. That should be fixed now.
* `export` had a usage line that had old flag names. The long help had the right
  flags, but the short help did not. Now they both do.
