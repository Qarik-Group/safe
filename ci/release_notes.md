# Bug Fixes

- `safe init` no longer requires a previously authenticated
  session with another vault, even though the token was going to
  be ignored anyway.

- `safe rm -r` now properly prompts for each path, without
  short-circuiting on a 'no', and has pretty color-fied output!

- `safe target` now honors the `--quiet` flag.

- `safe x509 help` now shows information about the `crl`
  sub-command, which we had scorned for some reason.
