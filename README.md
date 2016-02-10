safe - A Vault CLI
==================

![SAFE](docs/safe.png)

[Vault][vault] is an awesome project and it comes with superb
documentation, a rock-solid server component and a flexible and
capable command-line interface.

So, why `safe`?  To solve the following problems:

  1. Securely generate new SSH public / private keys
  2. Securely generate random RSA key pairs
  3. Auto-generate secure, random passwords
  4. Securely provide credentials, without files
  5. Dumping multiple paths

Primarily, these are things encountered in trying to build secure
BOSH deployments using Vault and [Spruce][spruce].

Usage
-----

`safe` operates by way of sub-commands.  To generate a new
2048-bit SSH keypair, and store it in `secret/ssh`:

```
safe ssh 2048 secret/ssh
```

To set non-sensitive keys, you can just specify them inline:

```
safe set secret/ssh username=system
```

Commands can be chained by separating them with the argument
terminator, `--`, so to both create a new SSH keypair and set the
username:

```
safe ssh 2048 secret/ssh -- set secret/ssh username=system
```

Auto-generated passwords are easy too:

```
safe gen secret/account passphrase
```

Sometimes, you just want to import passwords from another source
(like your own password manager), without the hassle of writing
files to disk or the risk of leaking credentials via the process
table or your shell history file.  For that, `safe` provides a
double-confirmation interactive mode:

```
safe set secret/ssl/ca passphrase
passphrase [hidden]:
passphrase [confirm]:
```

What you type will not be echoed back to the screen, and the
confirmation prompt is there to make sure your fingers didn't
betray you.

All operations (except for `delete`) are additive, so the
following:

```
safe set secret/x a=b c=d
```

is equivalent to this:

```
safe set secret/x a=b -- set secret/x c=d
```

Command Reference
------------------

### set path key\[=value\] \[key ...\]

Updates a single path with new keys.  Any existing keys that are
not specified on the command line are left intact.

You will be prompted to enter values for any keys that do not have
values.  This can be used for more sensitive credentials like
passwords, PINs, etc.

Example:

```
safe set secret/root username=root password
<prompts for 'password' here...>
```

### get path \[path ...\]

Retrieve and print the values of one or more paths, to standard
output.  This is most useful for piping credentials through
`keybase` or `pgp` for encrypting and sending to others.

```
safe get secret/root secret/whatever secret/key
--- # secret/root
username: root
password: it's a secret

--- # secret/whatever
whatever: is clever

--- # secret/key
private: |
   -----BEGIN RSA PRIVATE KEY-----
   ...
   -----END RSA PRIVATE KEY-----
public: |
  -----BEGIN RSA PUBLIC KEY-----
  ...
  -----END RSA PRIVATE KEY-----
```

### delete path \[path ...\]

Removes multiple paths from the Vault.

```
safe delete secret/unused
```

### move oldpath newpath

Move a secret from `oldpath` to `newpath`, a rename of sorts.

```
safe move secret/staging/user secret/prod/user
```

(or, more succinctly, using brace expansion):

```
safe move secret/{staging,prod}/user
```

Any credentials at `newpath` will be completely overwritten.  The
secret at `oldpath` will no longer exist.

### copy oldpath newpath

Copy a secret from `oldpath` to `newpath`.

```
safe copy secret/staging/user secret/prod/user
```

(or, as with `move`, using brace expansion):

```
save copy secret/{staging,prod}/user
```

Any credentials at `newpath` will be completely overwritten.  The
secret at `oldpath` will still exist after the copy.

### gen \[length\] path key

Generate a new, random password.  By default, the generated
password will be 64 characters long.

```
safe gen secret/account secretkey
```

To get a shorter password, only 16 characters long:

```
safe gen 16 secret/account password
```

### ssh \[nbits\] path \[path ...\]

Generate a new SSH RSA keypair, adding the keys "private" and
"public" to each path.  The public key will be encoded as an
authorized keys.  The private key is a PEM-encoded DER private
key.

By default, a 2048-bit key will be generated.  The `nbits`
parameter allows you to change that.

Each path gets a unique SSH keypair.

### rsa \[nbits\] path \[path ...\]

Generate a new RSA keypair, adding the keys "private" and "public"
to each path.  Both keys will be PEM-encoded DER.

By default, a 2048-bit key will be generated.  The `nbits`
parameter allows you to change that.

Each path gets a unique RSA keypair.





[vault]:  https://vaultproject.io
[spruce]: https://github.com/geofffranks/spruce
