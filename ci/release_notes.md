# Improvements

- A new command-line parser (`go-cli`) makes life easier for
  operators, and brings with it the potential to outfit existing
  commands with more flags.

# Bug Fixes

- `safe move`, `safe copy` and `safe delete` now no longer
  short-circuit long chains of sub-commands if they are recursive,
  not forced, and the operator says "no" at the confirm prompt.
  Instead, they only terminate the current sub-command,and resume
  execution with the next command in the chain.
