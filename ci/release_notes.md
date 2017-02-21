# Improvements

- Stronger cryptographic support in `safe gen`
  The `safe gen` command for generating random passwords now
  consults a cryptographically-secure PRNG when mashing strings
  together, so your passwords are even more uniformly distibuted.
