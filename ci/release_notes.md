# Improvements

- safe now canonicalizes all paths, removing leading / trailing
  slashes, and collapsing contiguous runs of 2 or more slashes
  down to just one.  Fixes #106
