# Improvements

* The `get`, `paths` and `tree` commands now support `--keys` option that
  outputs keys found under the specified path or paths.

* `safe get` has been refactored to have more meaningful output when
  requesting output from multiple paths and better supports mixes of path and
  path:key.  
  
  If more than one path is specified, the output will be YAML, with
  the base map key of the specified path, followed by the found (or specified)
  keys and associated values.  Single path behaviour stays the same (raw
  string for path:key, simple key:value YAML for path without specified key),
  but you can use the `--yaml` option to force it to use fully-qualified YAML.

# Bug Fixes
* Fixed a regression that broke `safe set` when setting a key to an empty
  string or referencing an empty file.

