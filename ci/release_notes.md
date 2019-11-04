# New Features

* `target` now has a `--no-strongbox` flag. This configures the target to treat
  the Vault installation as having no Strongbox on the VM. This affects `seal`,
  `unseal`, and `status`. Previously, and without this flag set, these commands
  would try to talk to a strongbox server to determine where all the nodes in the
  Vault cluster are, and then perform the command action to all of the nodes.
  With the flag set, the actions will just be applied to the targeted node without
  trying to use a Strongbox server.
* `target` now has a `--ca-cert` flag. This flag takes either a certificate
	string or a path to a file containing a certificate. The given certificate
	will be trusted as a root CA instead of the certificates in the system
	certificate pool. This flag can be specified multiple times to provide multiple
	CA certificates. The flag even works for passing through to the vault CLI with
	`safe vault`.

# Improvements

* Self-signed certificates (such as root-CAs) now have randomized serial
	numbers instead of using 1. This could previously cause issues if the
	self-signed certificate was regenerated, as the browser would throw an error
	for a duplicate serial number entry.
* `x509 show` now shows more information about the certificate, including if it
  is self-signed, if it is a CA, and the certificate's serial number.

# Bug Fixes

* Commands that recurse (e.g. `tree`/`paths`) would fail if access was denied
  to a subsection of the target tree. This was because an attempt to list a path
  would be made on a node that could be discovered, but Vault would return a
  permissions error when trying to list the particular node. This error is now
  handled in a way that allows the rest of the recursive output to succeed.
* The certificate serial number can no longer increment beyond 2^159, which it
  probably wasn't going to do anyway, but now it definitely won't.
