# New Commands

* `safe logout` - because `safe target` can no longer trivially be used to
	remove a token from an existing target (see below), `safe logout` is now here
	to do just that. It removes your cached auth token.

# Improvements

* `safe auth approle` now appears in the help listing for `safe auth`.
* `safe target` with two positional arguments would overwrite the token of an
  existing target even if the URL was the same. Now, if the URL is the same,
  the token will be kept.

# Bug Fixes

* Fixed a bug that was causing connections to the Vault to not be reused. This
	saves a considerable amount of traffic for commands that make a large amount
	of requests, like `safe tree`. As a result, considerable speed increases may
	be seen, especially in environments with low bandwdith or noticeable latency.
