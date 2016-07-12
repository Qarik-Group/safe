# Improvments

- Non-data messaging is now sent to standard error, so that it
  doesn't interfere with piping data to other safe commands.

- Add support for recursive move/copy/delete

  Users are now able to move, copy, or delete
  trees in Vault recursively, via the `-R` flag.
  This will prompt for confirmation. If you wish
  to ignore confirmation and copy/move/delete blindly,
  use the `-f` flag as well.

  NOTE: Vault does not appear to delete empty directories,
  which may lead to confusion after a move/delete, and
  the directories still appear. Any keys/values inside
  those directories have been removed.


- In order to properly display, copy, and move these, `safe`
  now makes a distinction between `node1/` and `node`. This
  will show up in `safe tree` as a blue directory node, and a
  green leaf node.

- `safe tree` and `safe paths` will now hide any intermediary
  nodes that do not have any leaf nodes underneath them (or any
  of their child-intermediary nodes).

- Added request debugging

# Bug Fixes

- Fixed a bug in `safe tree` and `safe paths` whereby
  the listings of `node1/` would be duplicated, and the listing
  of `node1` was overlooked.
