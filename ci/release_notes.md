## Improvements

- `safe` can now interrogate, seal and unseal HA backend Vaults,
  if you are running the [strongbox][strongbox] helper utility on
  your Consul+Vault deployment.  If you are running the shiny new
  [safe BOSH release][bosh], you get the server-side bits for free!

- `safe help` is better, and now provides a brief overview of the
  most common commands when run.  `safe commands` or `safe help
  commands` will list all of the known commands, and a `safe help
  <command>` will show detailed help specific to a single command.


[strongbox]: https://github.com/jhunt/go-strongbox
[bosh]:      https://github.com/cloudfoundry-community/safe-boshrelease
