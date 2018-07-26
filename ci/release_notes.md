# Improvements

- The secret key needn't be resident in the vault for `safe x509
  show` to work, which is great when you just want to show the
  cert someone gave you, that you didn't generate.

- `safe x509 ...` commands now properly handle bundled
  certificates, where the intermediary CAs are bundled with in a
  set of PEM blocks concatenated together.  Yay for corp X.509!
