# New Features

* Vault Enterprise Namespaces are now supported. Specify the `--namespace`
  flag to the `target` command when creating your target to have that
  target use the given namespace for all requests.

* `safe status` now has a `--err-sealed` (`-e`) flag. If specified, the
  command will return an error and a non-zero exit code if any of the
  Vaults are sealed. Script away!
