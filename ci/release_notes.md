# Bug Fixes

* `safe init` no longer skips unsealing if the `--json` flag is specified.
* `safe init` now waits a short period of time to give the Vault a reasonable
	chance to resolve leader election after unsealing.
