# New Features

- `safe local` will spin a Vault server for you, initialize and
  unseal it, and target it seamlessly.  You can opt for transient
  local vaults via `safe local --memory` or more durable vaults
  via `safe local --file path/to/store`.  You can name your local
  vaults, but `safe` took a creative writing course and it itching
  to use its newfound list of adjectives and nouns!

- `safe target` and `safe targets` now support a `--json` flag,
  for getting target information in a script-parseable format.

- Targets can now be specified by URL.  If you have multiple
  aliases for the same Vault (i.e. for specifying different auth
  parameters), you *must* use the aliases, since `safe` can't
  figure out which target you truly meant.
