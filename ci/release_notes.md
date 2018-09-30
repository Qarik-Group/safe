# Bug Fixes

* `safe auth -T <target>` now correctly indicates the target being
  authenticated.  It used to specify the current target instead of the
  specified target, even though it auth'ed to the specified target.  Now it no
  longer lies.
