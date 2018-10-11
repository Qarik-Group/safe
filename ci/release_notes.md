# New Features

* Safe honours the new `$SAFE_TARGET` environment variable to override the the safe target without using -T or calling `safe target`.  This can be used for scripts that want to target a specific vault without modifying the user's current target in `~/.saferc`
