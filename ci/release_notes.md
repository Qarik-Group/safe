# Improvements

- safe now canonicalizes all paths, removing leading / trailing
  slashes, and collapsing contiguous runs of 2 or more slashes
  down to just one.  Fixes #106

- `safe auth github` now presents a more useful error message
  about bad Personal Access Tokens, instead of dumping an API 500
  error on the poor unsuspecting user.
