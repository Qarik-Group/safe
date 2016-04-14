## New Features

- **Targets** - `safe` can now bounce between any number of
  Vaults easily, without getting the wires crossed.
- **Authentication** - `safe auth` now handles the authentication
  against the Vault (using either token, Github or LDAP backends)
- The new `safe env` sub-command exists to help troubleshoot
  auth/targeting issues.
- New `safe paste` sub-command is just like `safe set`, except it
  never asks for confirmation of what you just pasted from
  1password.
