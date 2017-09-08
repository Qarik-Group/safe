# New Features

- `safe rekey` now exists, to assist with re-keying a Vault with
  new unseal keys. It prompts for the old unseal keys, and when
  enough have been entered, the rekey occurs, and new unseal keys
  are printed out to the user. `--num-unseal-keys` and `--keys-to-unseal`
  can be used to configure how many unseal keys are created, and
  how many are required to unseal the vault.
  
  Additionally, GPG keys can be specified via the `--gpg` flag, to encrypt
  the unseal keys. When using this mode, each unseal key is encrypted
  by a different GPG key (you should specify more than one GPG key). Keys
  are looked up from the local GPG keyring. Each encrypted unseal key is
  output at the end, tied to the GPG key that was requested.

  For example:

  ```
  $ safe rekey --gpg user1@example.com --gpg user2@example.com
  Your Vault has been re-keyed. Please take note of your new unseal keys and store them safely!
  Unseal key for user1@example.com:
  REDACTED
  Unseal key for user2@example.com:
  REDACTED
  ```
