## Improvements

- `safe` can now interrogate, seal and unseal HA backend Vaults,
  if you are running the [strongbox][strongbox] helper utility on
  your Consul+Vault deployment.  If you are running the shiny new
  [safe BOSH release][bosh], you get the server-side bits for free!


[strongbox]: https://github.com/jhunt/go-strongbox
[bosh]:      https://github.com/cloudfoundry-community/safe-boshrelease
