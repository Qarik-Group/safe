# Bug Fixes

* safe recognizes performance standbys as standbys for the purpose of `safe status`.
* safe now won't use namespaces when trying to interface with /sys/health or /sys/seal-status, because these result in unsupported path errors from Vault.
* `safe ls` should now work with more versions of Vault when listing the root.
* `safe env --json` now exposes VAULT_NAMESPACE
* x509 show now displays data encipherment as data encipherment and not data encupherment, which is definitely not data encipherment.