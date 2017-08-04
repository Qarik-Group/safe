## New Features

- `safe auth userpass` allows users to authenticate using a username and
  password via the Vault [Username &
  Password](https://www.vaultproject.io/docs/auth/userpass.html) auth backend.

  This backend needs to be enabled first using `safe vault enable-auth
  userpass`, then each username/password needs to be added via:
  ```
  vault write auth/userpass/users/&lt;username> \
      password=&lt;password> \
      policies=&lt;user-policy>
  ```
