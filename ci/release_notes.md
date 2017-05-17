# New Features


- New global flag `--no-clobber` will throw a message up to the user
  that they tried to overwrite an existing credential.
  This is supported in all known write-causing commands,
  except `safe import`.

  When existing credentials are encountered, safe will exit 0,
  as it successfully avoided clobbering the credential.

  `--quiet` can be provided to suppress the clobber-noop warning
  messages
