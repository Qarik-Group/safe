## Improvements

- Safe operators now complain if they are directed to store a
  whole secret (with multiple subkeys) at a path:key, and refuse
  to create a situation they cannot handle.
