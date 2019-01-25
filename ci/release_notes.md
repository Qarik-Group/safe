# Bug Fixes

* safe commands no longer 403 when the auth token's policies does not have
access to sys endpoints. 
* paths and tree operations work correctly when the Vault has a secret at the
root of a mount.
