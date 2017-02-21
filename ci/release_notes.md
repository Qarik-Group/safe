# Improvements

- Stronger cryptographic support in `safe gen`
  The `safe gen` command for generating random passwords now
  consults a cryptographically-secure PRNG when mashing strings
  together, so your passwords are even more uniformly distibuted.

# Bug Fixes

- Fix (via temporary workaround) the `safe gen ... -- gen ...`
  chaining problem introduced by the `--policy` flag.  For now,
  the `--policy` flag has been removed while we architect a better
  long-term fix.
