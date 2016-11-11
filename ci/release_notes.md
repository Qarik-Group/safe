## Improvements

- `safe` can now interrogate, seal and unseal HA backend Vaults,
  if you are running the [strongbox][strongbox] helper utility on
  your Consul+Vault deployment.  If you are running the shiny new
  [safe BOSH release][bosh], you get the server-side bits for free!

- `safe help` is better, and now provides a brief overview of the
  most common commands when run.  `safe commands` or `safe help
  commands` will list all of the known commands, and a `safe help
  <command>` will show detailed help specific to a single command.

- New `safe exists` command allows you to write better tie-in
  scripts, by providing a non-zero exit code if a secret does not
  exist in the currently targeted Vault.

- Targets now remember whether you targeted them with the `-k`
  flag or not, so that if you wish to skip verification on a given
  Vault, you can do so indefinitely.  `safe target` and `safe
  targets` now sport sufficiently alarming messages indicating
  that certificate validation is not being performed.


[strongbox]: https://github.com/jhunt/go-strongbox
[bosh]:      https://github.com/cloudfoundry-community/safe-boshrelease
