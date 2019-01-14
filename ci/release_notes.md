# New Features

* `safe` now supports the versioned KV v2 backend! (Fixes #138)
* Commands that write will append new versions to versioned backends. 
* Commands that read will read the newest version (if undeleted) by default.
Older versions can be read with the `PATH^VERSION` syntax 
(i.e. `mysecret:mykey^2`). 
* Commands that delete will operate on the newest version by default. You can
target specific versions with the `PATH^VERSION` syntax. By default, versions
will be marked as deleted. They can be destroyed with the `-D` flag on `safe delete`.
All versions of a secret can be targeted with the `-a` flag on `safe delete`.
* `safe paths` and `safe tree` now has a `-q` flag. Because scripts using paths have
thus far assumed that only paths with accessible secrets will be returned, we need to
make sure that this behavior was preserved by default. However, Vault returns deleted
or destroyed secrets from list requests. Therefore, we have to make extra calls to make
sure that the latest version of the secret is alive. `-q` (quick) skips those checks to
get you a result faster, even though any secret with remaining metadata will be returned.
* `safe versions` is now a command. It shows all the existing version numbers for a
secret with their respective states. v1 backends are abstracted as versioned backends
that only ever have one living version.
* `safe undelete` is now a command. It undeletes a version that was marked as deleted.
It errs if you try it on a v1 backend because I can't get your cert back and _I'm sorry_.
* `safe revert` reads in an older version and writes it as the newest version of a secret.
It's a no-op if the newest version is specified. You can revert to versions marked as
deleted with the `-d` flag. This will cause the version to be undeleted, read, and then
redeleted. The resulting newest version will be left alive.

# Improvements

* Operations which walk the tree recursively now operate concurrently. This can lead
to a significant speed increase in environments where there is noticeable latency when
communicating with the Vault server. See: `tree`, `paths`, `delete -R`, etc
* x509 reissue and x509 renew now show up in `safe help x509`
* `safe curl`'s `--data-only` flag is now in the help (thanks, @lvets)
* We can `safe local` all the way up to Vault 1.0.1 (and possibly even beyond) (Fixes #171)
* `safe tree /` and `safe paths /` will now show all secrets across all KV mounts.

# Bug Fixes

* We can read non-strings out of the Vault again (Fixes #178).
* `safe rekey`'s key prompt is fixed and now won't just ask you for the first key `n` times

# Breaking Changes

* Exports are now in a new format. While this version of safe can import versions of the old
format, this version of safe will produce exports that older versions of safe will not be able
to import.
