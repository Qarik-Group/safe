# Improvement

- `safe seal` now accepts all seal keys on standard input, making
  it trivial to automate unsealing of the Vault (assuming you can
  safely handle the seal keys...)

- `safe init` and `safe rekey` now write the seal keys to the
  Vault, at `secret/vault/seal/keys`.  This behavior can be turned
  off by specifying the new `--no-persist` flag.
