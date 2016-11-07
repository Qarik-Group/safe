package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"time"
	"io/ioutil"
	"net/http/httputil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pborman/getopt"
	"github.com/starkandwayne/goutils/ansi"

	"github.com/starkandwayne/safe/auth"
	"github.com/starkandwayne/safe/prompt"
	"github.com/starkandwayne/safe/rc"
	"github.com/starkandwayne/safe/vault"
)

var Version string

func connect() *vault.Vault {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		ansi.Fprintf(os.Stderr, "@R{You are not targeting a Vault.}\n")
		ansi.Fprintf(os.Stderr, "Try @C{safe target http://your-vault alias}\n")
		ansi.Fprintf(os.Stderr, " or @C{safe target alias}\n")
		os.Exit(1)
	}

	if os.Getenv("VAULT_TOKEN") == "" {
		ansi.Fprintf(os.Stderr, "@R{You are not authenticated to a Vault.}\n")
		ansi.Fprintf(os.Stderr, "Try @C{safe auth ldap}\n")
		ansi.Fprintf(os.Stderr, " or @C{safe auth github}\n")
		ansi.Fprintf(os.Stderr, " or @C{safe auth token}\n")
		os.Exit(1)
	}

	v, err := vault.NewVault(addr, os.Getenv("VAULT_TOKEN"))
	if err != nil {
		ansi.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}
	return v
}

func main() {
	go Signals()

	r := NewRunner()
	r.Dispatch("version", func(command string, args ...string) error {
		if Version != "" {
			fmt.Fprintf(os.Stderr, "safe v%s\n", Version)
		} else {
			fmt.Fprintf(os.Stderr, "safe (development build)\n")
		}
		os.Exit(0)
		return nil
	})

	r.Dispatch("help", func(command string, args ...string) error {
		fmt.Fprintf(os.Stderr, `Usage: safe <cmd> <args ...>

    Valid subcommands are:

    targets
           List all Vaults that have been targeted.

    target [vault-address] name
           Target a new or existing Vault.

    auth [token|ldap|github]
           Authenticate against the currently targeted Vault.

    status
           Print the status of all backends to the current target.

    seal
           Seal all backend Vaults for the current target.

    unseal
           Unseal all backend Vaults for the current target.

    get path [path ...]
           Retrieve and print the values of one or more paths.

    set path key[=value] [key ...]
           Update a single path with new keys.  Any existing keys that are
           not specified on the command line are left intact. You will be
           prompted to enter values for any keys that do not have values.
           This can be used for more sensitive credentials like passwords,
           PINs, etc.

    paste path key[=value] [key ...]
           Works the same way as 'safe set', except that it does not
           prompt for confirmation of any values. This is used when you are
           pasting in data from an external source, and do not expect to
           mis-paste the data, to save a little time + headache.

    paths path [path ... ]
           Provide a flat listing of all reachable keys for each path.

    tree [-d] path [path ...]
           Provide a tree hierarchy listing of all reachable keys for each path.
           The optional -d argument will hide the leaf nodes in the tree, and
           only print the interior (directory) nodes.  This can lead to much more
           concise output, useful when you're trying to get your bearings.

    delete path [path ...]
           Remove multiple paths from the Vault.

    move oldpath newpath
           Move a secret from oldpath to newpath, a rename of sorts.

    copy oldpath newpath
           Copy a secret from oldpath to newpath.

    fmt format_type path oldkey newkey
           Take the value found at path:oldkey, and reformat it based
           on the provided flags (such as base64 encoding or crypt
           hashing). The resultant value will be stored into path:newkey.

           Valid format_types include the following:
           - crypt-sha512
           - base64

    gen [length] path key
           Generate a new, random password (length defaults to 64 chars).

    ssh [nbits] path [path ...]
           Generate a new SSH RSA keypair, adding the keys "private" and
           "public" to each path. The public key will be encoded as an
           authorized keys. The private key is a PEM-encoded DER private
           key. (nbits defaults to 2048 bits)

    rsa [nbits] path [path ...]
           Generate a new RSA keypair, adding the keys "private" and "public"
           to each path. Both keys will be PEM-encoded DER. (nbits defaults
           to 2048 bits)

    pki init
           Configure your Vault to do PKI via the other safe PKI commands.
           You have to run this command first, before you can use the 'cert',
           'revoke', 'ca-pem' and 'crl-pem' commands (unless you've already
           set up the pki backend on your Vault, in which case, cheers!)

    cert role path
           Generates a signed Certificate using Vault's PKI backend + Certifiate
           Authority using the provided role. The common name is derived from the
           last part of the path provided. Once issued, safe will store the
           private key, signed certificate, and serial number in the secret backend,
           located at the specified path.

           The --ttl, --ip-sans, --alt-names, and --exclude-cn-from-sans flags can
           be specified to customize how the certificate is generated.


    revoke path|serial
           Revokes a certificate from Vaults PKI backend, using the specified serial,
           or path to a secret containing the serial of the certificate. Once revoked,
           the CRL will be automatically updated inside Vault, but anything consuming
           the CRL should pull a new copy.

    ca-pem [path]
           Retrieves the PEM-encoded CA cert used in Vault's PKI backend for signing
           and issuing certificates. If path is supplied, sets the "ca-pem" key using the
           current CA cert inside the secret backend, at <path>.

    crl-pem [path]
           Retrieves the PEM-encoded Certificate Revocation List managed by
           Vaults PKI backend. If path is supplied, sets the "crl-pem" key using the
           current CRL inside the secret backend, at <path>.

    dhparam [bits] path
           Generates DH Params using OpenSSL, and the specified bit length. Defaults
           to 2048 bit primes. Primes are then stored in <path> under the 'dhparam-pem'
           key.

    prompt ...
           Echo the arguments, space-separated, as a single line to the terminal.

    import <export.file
           Read from STDIN an export file and write all of the secrets contained
           therein to the same paths inside the Vault

    export path [path ...]
           Export the given subtree(s) in a format suitable for migration (via a
           future import call), or long-term storage offline.

    vault  ...
           Runs arbitrary commands through the vault cli.
`)
		os.Exit(0)
		return nil
	})

	r.Dispatch("targets", func(command string, args ...string) error {
		if len(args) != 0 {
			return fmt.Errorf("USAGE: targets")
		}

		cfg := rc.Apply()
		wide := 0
		for name := range cfg.Aliases {
			if len(name) > wide {
				wide = len(name)
			}
		}

		var keys []string
		for name, _ := range cfg.Aliases {
			keys = append(keys, name)
		}

		fmt.Fprintf(os.Stderr, "\n")
		current := fmt.Sprintf("(*) @G{%%-%ds}\t@Y{%%s}\n", wide)
		other := fmt.Sprintf("    %%-%ds\t%%s\n", wide)
		sort.Strings(keys)
		for _, name := range keys {
			if name == cfg.Current {
				ansi.Fprintf(os.Stderr, current, name, cfg.Aliases[name])
			} else {
				ansi.Fprintf(os.Stderr, other, name, cfg.Aliases[name])
			}
		}
		fmt.Fprintf(os.Stderr, "\n")
		return nil
	})

	r.Dispatch("target", func(command string, args ...string) error {
		cfg := rc.Apply()
		if len(args) == 0 {
			if cfg.Current == "" {
				ansi.Fprintf(os.Stderr, "@R{No Vault currently targeted}\n")
			} else {
				ansi.Fprintf(os.Stderr, "Currently targeting @C{%s} at @C{%s}\n", cfg.Current, cfg.URL())
			}
			return nil
		}
		if len(args) == 1 {
			err := cfg.SetCurrent(args[0])
			if err != nil {
				return err
			}
			ansi.Fprintf(os.Stderr, "Now targeting @C{%s} at @C{%s}\n", cfg.Current, cfg.URL())
			return cfg.Write()
		}

		if len(args) == 2 {
			var err error
			if strings.HasPrefix(args[1], "http://") || strings.HasPrefix(args[1], "https://") {
				err = cfg.SetTarget(args[0], args[1])
			} else {
				err = cfg.SetTarget(args[1], args[0])
			}
			if err != nil {
				return err
			}
			ansi.Fprintf(os.Stderr, "Now targeting @C{%s} at @C{%s}\n", cfg.Current, cfg.URL())
			return cfg.Write()
		}

		return fmt.Errorf("USAGE: target [vault-address] name")
	})

	r.Dispatch("status", func(command string, args ...string) error {
		rc.Apply()
		v := connect()
		st, err := v.Strongbox()
		if err != nil {
			return fmt.Errorf("%s; are you targeting a `safe' installation?")
		}

		for addr, state := range st {
			if state == "sealed" {
				ansi.Printf("@R{%s is sealed}\n", addr)
			} else {
				ansi.Printf("@G{%s is unsealed}\n", addr)
			}
		}
		return nil
	})

	r.Dispatch("unseal", func(command string, args ...string) error {
		rc.Apply()
		v := connect()
		st, err := v.Strongbox()
		if err != nil {
			return fmt.Errorf("%s; are you targeting a `safe' installation?")
		}

		n := 0
		nkeys := 0
		for addr, state := range st {
			if state == "sealed" {
				n++
				v.URL = addr
				nkeys, err = v.SealKeys()
				if err != nil {
					return err
				}
			}
		}

		if n == 0 {
			ansi.Printf("@C{all vaults are already unsealed!}\n")
		} else {
			ansi.Printf("You need %d key(s) to unseal the vaults.\n\n", nkeys)
			keys := make([]string, nkeys)

			for i := 0; i < nkeys; i++ {
				_, key, err := keyPrompt(fmt.Sprintf("Key #%d", i+1), false)
				if err != nil {
					return err
				}
				keys[i] = key
			}

			for addr, state := range st {
				if state == "sealed" {
					ansi.Printf("unsealing @G{%s}...\n", addr)
					v.URL = addr
					if err = v.Unseal(keys); err != nil {
						return err
					}
				}
			}
		}

		return nil
	})

	r.Dispatch("seal", func(command string, args ...string) error {
		rc.Apply()
		v := connect()
		st, err := v.Strongbox()
		if err != nil {
			return fmt.Errorf("%s; are you targeting a `safe' installation?")
		}

		n := 0
		for _, state := range st {
			if state == "unsealed" {
				n++
			}
		}

		if n == 0 {
			ansi.Printf("@C{all vaults are already sealed!}\n")
		}

		for n > 0 {
			for addr, state := range st {
				if state == "unsealed" {
					v.URL = addr

					sealed, err := v.Seal();
					if err != nil {
						return err
					}
					if sealed {
						ansi.Printf("sealed @G{%s}...\n", addr)
						st[addr] = "sealed"
						n--
					}
				}
			}
			if n != 0 {
			time.Sleep(500 * time.Millisecond)
			}
		}

		return nil
	})

	r.Dispatch("env", func(command string, args ...string) error {
		rc.Apply()
		ansi.Fprintf(os.Stderr, "  @B{VAULT_ADDR}  @G{%s}\n", os.Getenv("VAULT_ADDR"))
		ansi.Fprintf(os.Stderr, "  @B{VAULT_TOKEN} @G{%s}\n", os.Getenv("VAULT_TOKEN"))
		return nil
	})

	r.Dispatch("auth", func(command string, args ...string) error {
		cfg := rc.Apply()

		method := "token"
		if len(args) > 0 {
			method = args[0]
			args = args[1:]
		}

		var token string
		var err error

		ansi.Fprintf(os.Stderr, "Authenticating against @C{%s} at @C{%s}\n", cfg.Current, cfg.URL())
		switch method {
		case "token":
			token, err = auth.Token(os.Getenv("VAULT_ADDR"))
			if err != nil {
				return err
			}
			break

		case "ldap":
			token, err = auth.LDAP(os.Getenv("VAULT_ADDR"))
			if err != nil {
				return err
			}
			break

		case "github":
			token, err = auth.Github(os.Getenv("VAULT_ADDR"))
			if err != nil {
				return err
			}
			break

		default:
			return fmt.Errorf("Unrecognized authentication method '%s'", method)
		}

		cfg.SetToken(token)
		return cfg.Write()

	}, "login")

	r.Dispatch("set", func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 2 {
			return fmt.Errorf("USAGE: set path key[=value] [key ...]")
		}
		v := connect()
		path, args := args[0], args[1:]
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		for _, set := range args {
			k, v, err := keyPrompt(set, true)
			if err != nil {
				return err
			}
			s.Set(k, v)
		}
		return v.Write(path, s)
	}, "write")

	r.Dispatch("paste", func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 2 {
			return fmt.Errorf("USAGE: paste path key[=value] [key ...]")
		}
		v := connect()
		path, args := args[0], args[1:]
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		for _, set := range args {
			k, v, err := keyPrompt(set, false)
			if err != nil {
				return err
			}
			s.Set(k, v)
		}
		return v.Write(path, s)
	})

	r.Dispatch("get", func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 1 {
			return fmt.Errorf("USAGE: get path [path ...]")
		}
		v := connect()
		for _, path := range args {
			s, err := v.Read(path)
			if err != nil {
				return err
			}
			//Don't show key if specific key was requested
			if _, key := vault.ParsePath(path); key != "" {
				value, err := s.SingleValue()
				if err != nil {
					return err
				}
				fmt.Printf("%s\n", value)
			} else {
				fmt.Printf("--- # %s\n%s\n", path, s.YAML())
			}
		}
		return nil
	}, "read", "cat")

	r.Dispatch("tree", func(command string, args ...string) error {
		rc.Apply()
		opt := vault.TreeOptions{
			UseANSI: true,
		}
		if len(args) > 0 && args[0] == "-d" {
			args = args[1:]
			opt.HideLeaves = true
		}
		if len(args) == 0 {
			args = append(args, "secret")
		}
		v := connect()
		for _, path := range args {
			tree, err := v.Tree(path, opt)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", tree.Draw())
		}
		return nil
	})

	r.Dispatch("paths", func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 1 {
			return fmt.Errorf("USAGE: paths path [path ...]")
		}
		v := connect()
		for _, path := range args {
			tree, err := v.Tree(path, vault.TreeOptions{
				UseANSI: false,
			})
			if err != nil {
				return err
			}
			for _, s := range tree.Paths("/") {
				fmt.Printf("%s\n", s)
			}
		}
		return nil
	})

	r.Dispatch("delete", func(command string, args ...string) error {
		rc.Apply()

		recurse, args := shouldRecurse(command, args...)

		if len(args) < 1 {
			return fmt.Errorf("USAGE: delete path [path ...]")
		}
		v := connect()
		for _, path := range args {
			if recurse {
				if err := v.DeleteTree(path); err != nil {
					return err
				}
			} else {
				if err := v.Delete(path); err != nil {
					return err
				}
			}
		}
		return nil
	}, "rm")

	r.Dispatch("export", func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 1 {
			return fmt.Errorf("USAGE: export path [path ...]")
		}
		v := connect()
		data := make(map[string]*vault.Secret)
		for _, path := range args {
			tree, err := v.Tree(path, vault.TreeOptions{})
			if err != nil {
				return err
			}
			for _, sub := range tree.Paths("/") {
				s, err := v.Read(sub)
				if err != nil {
					return err
				}
				data[sub] = s
			}
		}

		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(b))

		return nil
	})

	r.Dispatch("import", func(command string, args ...string) error {
		rc.Apply()
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		var data map[string]*vault.Secret
		err = json.Unmarshal(b, &data)
		if err != nil {
			return err
		}

		v := connect()
		for path, s := range data {
			err = v.Write(path, s)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %s\n", path)
		}
		return nil
	})

	r.Dispatch("move", func(command string, args ...string) error {
		rc.Apply()

		recurse, args := shouldRecurse(command, args...)

		if len(args) != 2 {
			return fmt.Errorf("USAGE: move oldpath newpath", args)
		}
		v := connect()

		if recurse {
			if err := v.MoveCopyTree(args[0], args[1], v.Move); err != nil {
				return err
			}
		} else {
			if err := v.Move(args[0], args[1]); err != nil {
				return err
			}
		}
		return nil
	}, "mv", "rename")

	r.Dispatch("copy", func(command string, args ...string) error {
		rc.Apply()

		recurse, args := shouldRecurse(command, args...)

		if len(args) != 2 {
			return fmt.Errorf("USAGE: copy oldpath newpath", args)
		}
		v := connect()

		if recurse {
			if err := v.MoveCopyTree(args[0], args[1], v.Copy); err != nil {
				return err
			}
		} else {
			if err := v.Copy(args[0], args[1]); err != nil {
				return err
			}
		}
		return nil
	}, "cp")

	r.Dispatch("gen", func(command string, args ...string) error {
		rc.Apply()
		length := 64
		if len(args) > 0 {
			if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
				length = int(u)
				args = args[1:]
			}
		}

		if len(args) != 2 {
			return fmt.Errorf("USAGE: gen [length] path key")
		}

		v := connect()
		path, key := args[0], args[1]
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		s.Password(key, length)

		if err = v.Write(path, s); err != nil {
			return err
		}
		return nil
	}, "auto")

	r.Dispatch("ssh", func(command string, args ...string) error {
		rc.Apply()
		bits := 2048
		if len(args) > 0 {
			if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
				bits = int(u)
				args = args[1:]
			}
		}

		if len(args) < 1 {
			return fmt.Errorf("USAGE: ssh [bits] path [path ...]")
		}

		v := connect()
		for _, path := range args {
			s, err := v.Read(path)
			if err != nil && !vault.IsNotFound(err) {
				return err
			}
			if err = s.SSHKey(bits); err != nil {
				return err
			}
			if err = v.Write(path, s); err != nil {
				return err
			}
		}
		return nil
	})

	r.Dispatch("rsa", func(command string, args ...string) error {
		rc.Apply()
		bits := 2048
		if len(args) > 0 {
			if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
				bits = int(u)
				args = args[1:]
			}
		}

		if len(args) < 1 {
			return fmt.Errorf("USAGE: rsa [bits] path [path ...]")
		}

		v := connect()
		for _, path := range args {
			s, err := v.Read(path)
			if err != nil && !vault.IsNotFound(err) {
				return err
			}
			if err = s.RSAKey(bits); err != nil {
				return err
			}
			if err = v.Write(path, s); err != nil {
				return err
			}
		}
		return nil
	})

	r.Dispatch("dhparam", func(command string, args ...string) error {
		rc.Apply()
		bits := 2048

		if len(args) > 0 {
			if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
				bits = int(u)
				args = args[1:]
			}
		}

		if len(args) < 1 {
			return fmt.Errorf("USAGE: dhparam [bits] path")
		}

		path := args[0]
		v := connect()
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		if err = s.DHParam(bits); err != nil {
			return err
		}
		return v.Write(path, s)
	}, "dh", "dhparams")

	r.Dispatch("prompt", func(command string, args ...string) error {
		fmt.Fprintf(os.Stderr, "%s\n", strings.Join(args, " "))
		return nil
	})

	r.Dispatch("vault", func(command string, args ...string) error {
		rc.Apply()

		cmd := exec.Command("vault", args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Run()
		if err != nil {
			return err
		}
		return nil
	})

	r.Dispatch("fmt", func(command string, args ...string) error {
		rc.Apply()

		if len(args) != 4 {
			return fmt.Errorf("USAGE: fmt format_type path oldkey newkey")
		}

		fmtType := args[0]
		path := args[1]
		oldKey := args[2]
		newKey := args[3]

		v := connect()
		s, err := v.Read(path)
		if err != nil {
			return err
		}
		if err = s.Format(oldKey, newKey, fmtType); err != nil {
			if vault.IsNotFound(err) {
				return fmt.Errorf("%s:%s does not exist, cannot create %s encoded copy at %s:%s", path, oldKey, fmtType, path, newKey)
			}
			return fmt.Errorf("Error encoding %s:%s as %s: %s", path, oldKey, fmtType, err)
		}

		return v.Write(path, s)
	})

	r.Dispatch("pki", func(command string, args ...string) error {
		if len(args) != 1 || args[0] != "init" {
			return fmt.Errorf("USAGE: pki setup")
		}

		rc.Apply()
		inAltUnits := regexp.MustCompile(`^(\d+)([dDyY])$`)

		v := connect()
		params := make(map[string]interface{})

		ttl := prompt.Normal("@C{Certificate Lifetime}: ")
		if ttl == "" {
			ttl = "10y"
		}
		if match := inAltUnits.FindStringSubmatch(ttl); len(match) == 3 {
			u, err := strconv.ParseUint(match[1], 10, 16)
			if err != nil {
				return err
			}

			switch match[2] {
			case "d":
				fallthrough
			case "D":
				ttl = fmt.Sprintf("%dh", u*24)

			case "y":
				fallthrough
			case "Y":
				ttl = fmt.Sprintf("%dh", u*365*24)

			default:
				return fmt.Errorf("Unrecognized time unit '%s'\n", match[2])
			}
		}
		params["max_lease_ttl"] = ttl

		mounted, err := v.IsMounted("pki", "pki")
		if err != nil {
			return err
		}

		/* Mount the PKI backend to `pki/` */
		err = v.Mount("pki", "pki", params)
		if err != nil {
			return err
		}

		if !mounted {
			/* First Time! */
			common_name := prompt.Normal("@C{Common Name (FQDN)}: ")

			/* Generate the CA certificate */
			m := make(map[string]string)
			m["common_name"] = common_name
			m["ttl"] = ttl

			err := v.Configure("pki/root/generate/internal", m)
			if err != nil {
				return err
			}

			/* Advertise the CRL / Issuer URLs */
			m = make(map[string]string)
			m["issuing_certificates"] = fmt.Sprintf("%s/v1/pki/ca", v.URL)
			m["crl_distribution_points"] = fmt.Sprintf("%s/v1/pki/crl", v.URL)

			err = v.Configure("pki/config/urls", m)
			if err != nil {
				return err
			}

			/* Set up a default role, with the same domain as the CA */
			m = make(map[string]string)
			m["allowed_domains"] = common_name
			m["allow_subdomains"] = "true"
			m["max_ttl"] = ttl

			err = v.Configure("pki/roles/default", m)
			if err != nil {
				return err
			}
		}

		return nil
	})

	r.Dispatch("crl-pem", func(command string, args ...string) error {
		rc.Apply()

		v := connect()
		if mounted, _ := v.IsMounted("pki", "pki"); !mounted {
			return fmt.Errorf("The PKI backend has not been configured.  Try running `safe pki init`\n")
		}

		pem, err := v.RetrievePem("crl")
		if err != nil {
			return err
		}

		if len(args) > 0 {
			path := args[0]
			s, err := v.Read(path)
			if err != nil && !vault.IsNotFound(err) {
				return err
			}
			s.Set("crl-pem", string(pem))
			return v.Write(path, s)
		} else {
			if len(pem) == 0 {
				ansi.Fprintf(os.Stderr, "@Y{No CRL exists yet}\n")
			} else {
				fmt.Fprintf(os.Stdout, "%s\n", pem)
			}
		}
		return nil
	})

	r.Dispatch("ca-pem", func(command string, args ...string) error {
		rc.Apply()

		v := connect()
		if mounted, _ := v.IsMounted("pki", "pki"); !mounted {
			return fmt.Errorf("The PKI backend has not been configured.  Try running `safe pki init`\n")
		}

		pem, err := v.RetrievePem("ca")
		if err != nil {
			return err
		}

		if len(args) > 0 {
			path := args[0]
			s, err := v.Read(path)
			if err != nil && !vault.IsNotFound(err) {
				return err
			}
			s.Set("ca-pem", string(pem))
			return v.Write(path, s)
		} else {
			if len(pem) == 0 {
				ansi.Fprintf(os.Stderr, "@Y{No CA exists yet}\n")
			} else {
				if len(pem) == 0 {
					ansi.Fprintf(os.Stderr, "@Y{No CA exists yet}\n")
				} else {
					fmt.Fprintf(os.Stdout, "%s", pem)
				}
			}
		}
		return nil
	})

	r.Dispatch("cert", func(command string, args ...string) error {
		rc.Apply()

		ttl := getopt.StringLong("ttl", 0, "", "Vault-compatible time specification for the length the Cert is valid for")
		ip_sans := getopt.StringLong("ip-sans", 0, "", "Comma-separated list of IP SANs")
		alt_names := getopt.StringLong("alt-names", 0, "", "Comma-separated list of SANs")
		exclude_cn_from_sans := getopt.BoolLong("exclude-cn-from-sans", 0, "", "Exclude the common_name from DNS or Email SANs")

		args = append([]string{"safe " + command}, args...)

		var opts = getopt.CommandLine
		var parsed []string
		for {
			opts.Parse(args)
			if opts.NArgs() == 0 {
				break
			}
			parsed = append(parsed, opts.Arg(0))
			args = opts.Args()
		}

		args = parsed

		params := vault.CertOptions{
			TTL:               *ttl,
			IPSans:            *ip_sans,
			AltNames:          *alt_names,
			ExcludeCNFromSans: *exclude_cn_from_sans,
		}

		if len(args) != 2 {
			return fmt.Errorf("USAGE: cert role path")
		}

		v := connect()
		if mounted, _ := v.IsMounted("pki", "pki"); !mounted {
			return fmt.Errorf("The PKI backend has not been configured.  Try running `safe pki init`\n")
		}

		role, path := args[0], args[1]
		return v.CreateSignedCertificate(role, path, params)
	})

	r.Dispatch("revoke", func(command string, args ...string) error {
		rc.Apply()

		if len(args) != 1 {
			return fmt.Errorf("USAGE: revoke path|serial")
		}

		v := connect()
		if mounted, _ := v.IsMounted("pki", "pki"); !mounted {
			return fmt.Errorf("The PKI backend has not been configured.  Try running `safe pki init`\n")
		}

		return v.RevokeCertificate(args[0])
	})

	r.Dispatch("curl", func(command string, args ...string) error {
		rc.Apply()

		if len(args) < 2 {
			return fmt.Errorf("USAGE: curl method path [data]")
		}

		v := connect()
		res, err := v.Curl(strings.ToUpper(args[0]), args[1], []byte(strings.Join(args[2:], " ")))
		if err != nil {
			return err
		}

		r, _ := httputil.DumpResponse(res, true)
		fmt.Fprintf(os.Stdout, "%s\n", r)
		return nil
	})

	insecure := getopt.BoolLong("insecure", 'k', "Disable SSL/TLS certificate validation")
	showVersion := getopt.BoolLong("version", 'v', "Print version information and exit")
	showHelp := getopt.BoolLong("help", 'h', "Get some help")
	opts := getopt.CommandLine
	opts.Parse(os.Args)

	var args []string
	if *showHelp {
		args = []string{"help"}

	} else if *showVersion {
		args = []string{"version"}

	} else if opts.NArgs() == 0 {
		args = []string{"help"}

	} else {
		args = opts.Args()
	}

	if *insecure {
		os.Setenv("VAULT_SKIP_VERIFY", "1")
	}

	if err := r.Run(args...); err != nil {
		if strings.HasPrefix(err.Error(), "USAGE") {
			ansi.Fprintf(os.Stderr, "@Y{%s}\n", err)
		} else {
			ansi.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		}
		os.Exit(1)
	}
}

func shouldRecurse(cmd string, args ...string) (bool, []string) {
	var recursiveMode, forceMode *bool

	forceMode = getopt.BoolLong("force", 'f', "Disable confirmation prompting")
	recursiveMode = getopt.BoolLong("recursive", 'R', "Enable recursion")

	args = append([]string{"safe " + cmd}, args...)

	var opts = getopt.CommandLine
	var parsed []string
	for {
		opts.Parse(args)
		if opts.NArgs() == 0 {
			break
		}
		parsed = append(parsed, opts.Arg(0))
		args = opts.Args()
	}

	args = parsed

	if *recursiveMode && !*forceMode {
		fmt.Printf("Are you sure you wish to recursively %s %s? (y/n) ", cmd, strings.Join(args, " "))
		reader := bufio.NewReader(os.Stdin)
		y, _ := reader.ReadString('\n')
		y = strings.TrimSpace(y)
		if y != "y" && y != "yes" {
			fmt.Printf("Aborting...\n")
			os.Exit(0)
		}
	}

	return *recursiveMode, args
}
