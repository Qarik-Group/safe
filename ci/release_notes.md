# New Features

- `safe target` and `safe targets` now support a `--json` flag,
  for getting target information in a script-parseable format.

- Targets can now be specified by URL.  If you have multiple
  aliases for the same Vault (i.e. for specifying different auth
  parameters), you *must* use the aliases, since `safe` can't
  figure out which target you truly meant.
