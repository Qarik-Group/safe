# New Features

* `safe auth` now supports a `--path` flag. This allows auth to be done against
  an auth backend that is not mounted at the default location.

# Improvements

* Safe no longer ignores the path segment of the target URL for most commands.
  It is now prefixed onto the Vault API portion of the path. For example, `safe
  ls` with target URL `https://myvault.com/foo` will query
  `https://myvault.com/foo/v1/secret` (sort of, but it works as a visual
  example).
