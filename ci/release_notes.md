# Bug Fixes

- `safe target` no longer cares if your current target is valid
  before overwriting it.

# Breaking Changes

These are things that should have been done in 1.0.0 to maintain 
backward compatibility with older versions of safe`s export calls.

- `safe export` will now make a v1-style export if it is able to.
These can be imported by older versions of safe.
- `safe export`'s `--shallow` and `--only-alive` flags are now the
default behaviors. They can be flipped with the new `--all` and `--deleted`
flags, respectively.
