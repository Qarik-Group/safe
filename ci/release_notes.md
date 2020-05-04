# Improvements

* safe x509 renew can now set new key usages for the renewed key.
* When using an SSH proxy, safe now handles the ssh `known_hosts` file better.
  It can now handle whe  the known_hosts file is empty, and also safe now adds
  newlines to lines that it adds.
