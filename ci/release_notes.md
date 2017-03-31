# Changes

* `delete` now gives you back a non-zero return code if it couldn't find the thing
you wanted it to delete. If this seems like something you don't want to happen,
adding the `-f` flag will cause it to fail silently like it used to.

# Improvements

* `delete`, `move`, `copy`, and `gen` now allow you to touch specific keys in a
secret. Give the commands their expected paths in a secret:key format and it
should all work the way you expect. 
* `gen` can now take multiple paths as arguments, and it will make passwords for
all those places for you.
* `gen` now has a `-l` flag to specify length whereever you want. The old method
of putting an integer as the first argument still works, but if you want to be
explicit about it, you can put `-l <length` anywhere after the command name.
* All commands will now take a `-h` flag to print out their respective help 
dialogues.
* Attempting to `delete`, `move` a folder path without `-R` specified now gives
you a more helpful error telling you that you've targeted a folder instead of a 
secret.

# Bug Fixes

* Some time back, we made it so that the help wouldn't print if the user simply 
ran `safe` without any arguments. That was an accident. That's fixed now.
