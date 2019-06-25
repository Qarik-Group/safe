# New Features

* SSH tunneling is now supported as a proxy. `ssh+socks5://` is the scheme you'll
  want to use in your proxy environment variables to take advantage of this. For
  more information on how to use this, check out `safe envvars`

* `SAFE_ALL_PROXY` is now a supported environment variable - it will set the values
  for both `HTTP_PROXY` and `HTTPS_PROXY`.
