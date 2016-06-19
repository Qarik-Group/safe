## Improvements

- New `-k / --insecure` flag for forcibly skipping the SSL/TLS
  certificate verification phase of Vault communication, in case
  you have a self-signed certificate and don't want to keep
  setting `$VAULT_SKIP_VERIFY` manually (Issue #23).
- Secure prompts now accept input from standard input.  This
  allows scripted installations of Vault (to a degree) since the
  `safe auth` step can be fed data from a file (Issue #21).
- `safe target` now inspects the alias and url that you give it,
  and if it finds that you have switched them, it reorders them
  for you.  (Issue #25).
- safe now falls back to using `$VAULT_ADDR` and `~/.vault-token`
  (if present) when there is no ~/.saferc, allowing people to
  transition from using the vault CLI to use safe with targets
  (Issue #11).

## Bug Fixes

- Duplication of subtrees is now fixed.  Previously, if you had a
  path, say `secret/aws` that help attributes of its own (like
  `access_key` and `secret_key`), but you also had a path like
  `secret/aws/environment/stuff`, the `tree` subcommand would list
  the aws subtree twice: once for the path itself (including all
  children) and a second time for the component of the larger
  path.  This has been fixed (Issue #24).
