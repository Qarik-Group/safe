# Bug Fixes

* `safe auth -T <target>` now correctly indicates the target being
  authenticated.  It used to specify the current target instead of the
  specified target, even though it auth'ed to the specified target.  Now it no
  longer lies.

* `safe targets --json` reported the opposite state of the skip-ssh-verify
  condition -- this has been corrected.

# Improvements

* `safe rekey` now cancels an existing rekey operation.

* `safe x509 issue`, `safe x509 renew`, and `safe x509 reissue` now have a
  `--sig-algorithm` flag that allows the user to specify which signature
  algorithm to sign the certificate with. Previously, this was hardcoded
  to be SHA512 with RSA - now that is simply the default value.

* `safe x509 show` now shows the algorithm that the certificate was signed with.

# Backend Changes

* The code that actually talks to Vault was switched to a library for smoother
  development moving forward. This shouldn't cause any behavioral changes,
  but some error messaging may have changed. If some error messaging is unclear,
  (or if something broke, of course) drop us an issue.
