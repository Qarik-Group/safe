# New Features

* `safe uuid` is a new command that will generate a UUIDv4 and insert it into
the specified path at the Vault. (thanks @gerardocorea)
* `safe option` allows you to view and edit new safe CLI global options.
Currently, the only option is `manage_vault_token`, which will have safe
change the .vault-token file that the Vault CLI uses. (thanks @daviddob)

# Improvements

* `safe versions` now shows when versions in a KVv2 backend were created.