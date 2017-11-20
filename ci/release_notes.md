## New Features

- The `~/.saferc` format got an overhaul that allows `safe` to
  target the same Vault URL under different aliases (and hence,
  store different auth tokens retrieved by different methods).

- The new `-T` / `--target` global flag allows you to temporarily
  set your Safe target, just for the duration of the rest of the
  command chain.  This fixes a race condition reported in #100,
  and allows the idiom `safe -T old export | safe -T new import`
  to work without corrupting your `~/.saferc` files.

## Improvements

- Safe operators now complain if they are directed to store a
  whole secret (with multiple subkeys) at a path:key, and refuse
  to create a situation they cannot handle.

- `safe` is more intelligent about when colorization occurs, thanks
  to updates in the upstream ANSI libraries.
