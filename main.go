package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http/httputil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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
	r.HelpTopic("usage", `Usage: safe <command> [options...]

Valid subcommands are:

    @C{targets}     List all Vaults that have been targeted
    @C{target}      Target a new or existing Vault
    @C{auth}        Authenticate against the currently targeted Vault

    @G{tree}        Print a tree listing of all reachable keys for each path

    @G{read}        Retrieve and print the values of one or more paths
    @R{write}       Update a single path with new keys

    @R{delete}      Remove multiple paths from the Vault
    @R{move}        Move a secret from one path to another
    @R{copy}        Copy a secret from one path to another

    @R{gen}         Generate a new, random secret
    @R{ssh}         Generate a new SSH RSA keypair
    @R{rsa}         Generate a new RSA keypair

    @G{export}      Export one or more paths to a backup file
    @R{import}      Import a Vault backup file

    @R{vault}       Run arbitrary commands through the Vault CLI

Try 'safe help <thing>' for detailed information,
 or 'safe commands' for a list of all commands.
`)

	r.Dispatch("version", &Help{
		Summary: "Print the version of the safe CLI",
		Usage:   "safe version",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		if Version != "" {
			fmt.Fprintf(os.Stderr, "safe v%s\n", Version)
		} else {
			fmt.Fprintf(os.Stderr, "safe (development build)\n")
		}
		os.Exit(0)
		return nil
	})

	r.Dispatch("help", nil, func(command string, args ...string) error {
		if len(args) == 0 {
			args = append(args, "usage")
		}
		if len(args) > 1 {
			ansi.Fprintf(os.Stderr, "@R{too many arguments to `safe help'}\n")
			r.Help(os.Stderr, "usage")
			os.Exit(1)
			return nil
		}
		r.Help(os.Stderr, args[0])
		os.Exit(0)
		return nil
	})

	r.Dispatch("targets", &Help{
		Summary: "List all targeted Vaults",
		Usage:   "safe targets",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		if len(args) != 0 {
			r.ExitWithUsage("targets")
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

	r.Dispatch("target", &Help{
		Summary: "Target a new Vault, or set your current Vault target",
		Usage:   "safe target [URL] [ALIAS]",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
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

		r.ExitWithUsage("target")
		return nil
	})

	r.Dispatch("status", &Help{
		Summary: "Print the status of the current targets backend nodes",
		Usage:   "safe status",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
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

	r.Dispatch("unseal", &Help{
		Summary: "Unseal the current target",
		Usage:   "safe unseal",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
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

	r.Dispatch("seal", &Help{
		Summary: "Seal the current target",
		Usage:   "safe seal",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
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

					sealed, err := v.Seal()
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

	r.Dispatch("env", &Help{
		Summary: "Print the VAULT_ADDR and VAULT_TOKEN for the current target",
		Usage:   "safe env",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		rc.Apply()
		ansi.Fprintf(os.Stderr, "  @B{VAULT_ADDR}  @G{%s}\n", os.Getenv("VAULT_ADDR"))
		ansi.Fprintf(os.Stderr, "  @B{VAULT_TOKEN} @G{%s}\n", os.Getenv("VAULT_TOKEN"))
		return nil
	})

	r.Dispatch("auth", &Help{
		Summary: "Authenticate to the current target",
		Usage:   "safe auth (token|github|ldap)",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
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

	r.Dispatch("set", &Help{
		Summary: "Create or update a secret",
		Usage:   "safe set PATH NAME=[VALUE] [NAME ...]",
		Type:    DestructiveCommand,
		Description: `
Update a single path in the Vault with new or updated named attributes.
Any existing name/value pairs not specified on the command-line will be
left alone, with their original values.

You will be prompted to provide (and confirm) any values that are omitted.
This can be useful for sensitive credential like passwords and PINs, when
you don't want the value to show up in your ~/.bash_history, or in the
process table.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 2 {
			r.ExitWithUsage("set")
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

	r.Dispatch("paste", &Help{
		Summary: "Create or update a secret",
		Usage:   "safe paste PATH NAME=[VALUE] [NAME ...]",
		Type:    DestructiveCommand,
		Description: `
Works just like 'safe set', updating a single path in the Vault with new or
updated named attributes.  Any eisting name/value pairs not specified on the
command-line will be left alone, with their original values.

You will be prompted to provide any values that are omitted, but unlike the
'safe set' command, you will not be asked to confirm those values.  This makes
sense when you are pasting in credentials from an external password manager
like 1password or Lastpass.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 2 {
			r.ExitWithUsage("paste")
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

	r.Dispatch("get", &Help{
		Summary: "Retrieve and print the values of one or more paths",
		Usage:   "safe get PATH [PATH ...]",
		Type:    NonDestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 1 {
			r.ExitWithUsage("get")
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

	r.Dispatch("tree", &Help{
		Summary: "Print a tree listing of one or more paths",
		Usage:   "safe tree [-d] [PATH ...]",
		Type:    NonDestructiveCommand,
		Description: `
Walks the hierarchy of secrets stored underneath a given path, listing all
reachable name/value pairs.  If '-d' is given, only the containing folders
will be printed; this more concise output can be useful when you're trying
to get your bearings.
`,
	}, func(command string, args ...string) error {
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

	r.Dispatch("paths", &Help{
		Summary: "Print all of the known paths, one per line",
		Usage:   "safe paths PATH [PATH ...]",
		Type:    NonDestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 1 {
			args = append(args, "secret")
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

	r.Dispatch("delete", &Help{
		Summary: "Remove one or more path from the Vault",
		Usage:   "safe delete [-R] PATH [PATH ...]",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply()

		recurse, args := shouldRecurse(command, args...)

		if len(args) < 1 {
			r.ExitWithUsage("delete")
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

	r.Dispatch("export", &Help{
		Summary: "Export one or more subtrees for migration / backup purposes",
		Usage:   "safe export PATH [PATH ...]",
		Type:    NonDestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 1 {
			args = append(args, "secret")
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

	r.Dispatch("import", &Help{
		Summary: "Import name/value pairs into the current Vault",
		Usage:   "safe import <backup/file.json",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
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

	r.Dispatch("move", &Help{
		Summary: "Move a secret from one path to another",
		Usage:   "safe move [-R] OLD-PATH NEW-PATH",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply()

		recurse, args := shouldRecurse(command, args...)

		if len(args) != 2 {
			r.ExitWithUsage("move")
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

	r.Dispatch("copy", &Help{
		Summary: "Copy a secret from one path to another",
		Usage:   "safe copy [-R] OLD-PATH NEW-PATH",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply()

		recurse, args := shouldRecurse(command, args...)

		if len(args) != 2 {
			r.ExitWithUsage("copy")
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

	r.Dispatch("gen", &Help{
		Summary: "Generate a random password",
		Usage:   "safe gen [LENGTH] PATH KEY",
		Type:    DestructiveCommand,
		Description: `
LENGTH defaults to 64 characters.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		length := 64
		if len(args) > 0 {
			if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
				length = int(u)
				args = args[1:]
			}
		}

		if len(args) != 2 {
			r.ExitWithUsage("gen")
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

	r.Dispatch("ssh", &Help{
		Summary: "Generate one or more new SSH RSA keypair(s)",
		Usage:   "safe ssh [NBITS] PATH [PATH ...]",
		Type:    DestructiveCommand,
		Description: `
For each PATH given, a new SSH RSA public/private keypair will be generated,
with a key strength of NBITS (which defaults to 2048).  The private keys will
be stored under the 'private' name, as a PEM-encoded RSA private key, and the
public key, formatted for use in an SSH authorized_keys file, under 'public'.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		bits := 2048
		if len(args) > 0 {
			if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
				bits = int(u)
				args = args[1:]
			}
		}

		if len(args) < 1 {
			r.ExitWithUsage("ssh")
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

	r.Dispatch("rsa", &Help{
		Summary: "Generate a new RSA keypair",
		Usage:   "safe rsa [NBITS] PATH [PATH ...]",
		Type:    DestructiveCommand,
		Description: `
For each PATH given, a new RSA public/private keypair will be generated with a,
key strength of NBITS (which defaults to 2048).  The private keys will be stored
under the 'private' name, and the public key under the 'public' name.  Both will
be PEM-encoded.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		bits := 2048
		if len(args) > 0 {
			if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
				bits = int(u)
				args = args[1:]
			}
		}

		if len(args) < 1 {
			r.ExitWithUsage("rsa")
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

	r.Dispatch("dhparam", &Help{
		Summary: "Generate Diffie-Helman key exchange parameters",
		Usage:   "safe dhparam [NBITS] PATH",
		Type:    DestructiveCommand,
		Description: `
NBITS defaults to 2048.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		bits := 2048

		if len(args) > 0 {
			if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
				bits = int(u)
				args = args[1:]
			}
		}

		if len(args) < 1 {
			r.ExitWithUsage("dhparam")
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

	r.Dispatch("prompt", &Help{
		Summary: "Print a prompt (useful for scripting safe command sets)",
		Usage:   "safe echo Your Message Here:",
		Type:    NonDestructiveCommand,
	}, func(command string, args ...string) error {
		fmt.Fprintf(os.Stderr, "%s\n", strings.Join(args, " "))
		return nil
	})

	r.Dispatch("vault", &Help{
		Summary: "Run arbitrary Vault CLI commands against the current target",
		Usage:   "safe vault ...",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
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

	r.Dispatch("fmt", &Help{
		Summary: "Reformat an existing name/value pair, into a new name",
		Usage:   "safe fmt FORMAT PATH OLD-NAME NEW-NAME",
		Type:    DestructiveCommand,
		Description: `
Take the value stored at PATH/OLD-NAME, format it a different way, and
then save it at PATH/NEW-NAME.  This can be useful for generating a new
password (via 'safe gen') and then crypt'ing it for use in /etc/shadow,
using the 'crypt-sha512' format.

Supported formats:

    base64          Base64 encodes the value
    crypt-sha512    Salt and hash the value, using SHA-512, in crypt format.

`,
	}, func(command string, args ...string) error {
		rc.Apply()

		if len(args) != 4 {
			r.ExitWithUsage("fmt")
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

	r.Dispatch("pki", &Help{
		Summary: "Configure the PKI backend on the target Vault",
		Usage:   "safe pki init",
		Type:    DestructiveCommand,
		Description: `
Configure your Vault to do PKI via the other safe PKI commands.

You have to run this command first, before you can use the 'cert',
'revoke', 'ca-pem' and 'crl-pem' commands (unless you've already set
up the pki backend on your Vault, in which case, cheers!)
`,
	}, func(command string, args ...string) error {
		if len(args) != 1 || args[0] != "init" {
			r.ExitWithUsage("pki")
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

	r.Dispatch("crl-pem", &Help{
		Summary: "Retrieve the Vault Certificate Revocation List",
		Usage:   "safe crl-pem [PATH]",
		Type:    NonDestructiveCommand,
		Description: `
@M{(You must run 'safe pki init' before you can use this command)}

Retrieve the Certificate Revocation List (CRL) from the Vault PKI backend.
This list identifies which of the certificates that Vault has issued have
since been revoked, and should not be trusted, despite their validity.

The CRL will be printed to standard output, as a PEM-encoded value.

If you supply a PATH, the CRL will not be printed, but will be saved at that
path, under the name 'crl-pem'.
`,
	}, func(command string, args ...string) error {
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

	r.Dispatch("ca-pem", &Help{
		Summary: "Retrieve the Vault Certificate Authority (CA) Certificate",
		Usage:   "safe ca-pem [PATH]",
		Type:    NonDestructiveCommand,
		Description: `
@M{(You must run 'safe pki init' before you can use this command)}

Retrieve the Certificate Authority (CA) certificate from the Vault PKI
backend.  To take full advantage of Vault-issued certificates, you will
need to install the CA certificate in your trusted certificates bundle.

The CA certificate will be printed to standard output, as a PEM-encoded
value.

If you supply a PATH, the CA certificate will not be printed, but will be
saved at that path, under the name 'ca-pem'.
`,
	}, func(command string, args ...string) error {
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

	r.Dispatch("cert", &Help{
		Summary: "Issue a Certificate using the Vault PKI backend",
		Usage:   "safe cert [OPTIONS] ROLE PATH",
		Type:    DestructiveCommand,
		Description: `
@M{(You must run 'safe pki init' before you can use this command)}

Generate a new private key, and then issue a certificate, signed by the
Vault Certificate Authority (CA).  The common name of the new certificate
will be based on the last part of the provided PATH, so if you want to
issue a certificate for secure.example.com, you want to use something like

    safe cert example.com secret/certs/secure.example.com

(Assuming you set up 'example.com' as your CA FQDN when you went through
 the 'safe pki init' setup stage.)

The following options are recognized:

  --ttl                    How long the cert should be valid for
                           (i.e. '90d', '10h', etc.)

  --alt-names              A comma-separated list of alternate DNS
                           names (SANs) to include in the certificate.

  --ip-sans                Comma-separated list of IP addresses to
                           include in the certificate as IP SANs

  --exclude-cn-from-sans   Exclude the certificate's common name (CN)
                           from the Subject Alternate Name list.

Once generated, the new private key will be stored under the name 'key',
the certificate will be under 'cert', a combined PEM containing both will
be saved as 'combined', and the certificate serial number under 'serial'.
`,
	}, func(command string, args ...string) error {
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
			r.ExitWithUsage("cert")
		}

		v := connect()
		if mounted, _ := v.IsMounted("pki", "pki"); !mounted {
			return fmt.Errorf("The PKI backend has not been configured.  Try running `safe pki init`\n")
		}

		role, path := args[0], args[1]
		return v.CreateSignedCertificate(role, path, params)
	})

	r.Dispatch("revoke", &Help{
		Summary: "Revoke a Vault-issued Certificate",
		Usage:   "safe revoke [PATH | SERIAL]",
		Type:    DestructiveCommand,
		Description: `
@M{(You must run 'safe pki init' before you can use this command)}

Revoke a certificate that was issued by the Vault PKI backend.  You can
specify which certificate to revoke by using its serial number, or by
providing the PATH in the Vault where the certificate is stored.

After the certificate is revoked, it will be added to the Certificate
Revocation List (CRL) automatically.  Note that this will only update the
Vault's copy of the CRL -- any external copies of the the list will need
to be refreshed via the 'safe crl-pem' command.
`,
	}, func(command string, args ...string) error {
		rc.Apply()

		if len(args) != 1 {
			r.ExitWithUsage("revoke")
		}

		v := connect()
		if mounted, _ := v.IsMounted("pki", "pki"); !mounted {
			return fmt.Errorf("The PKI backend has not been configured.  Try running `safe pki init`\n")
		}

		return v.RevokeCertificate(args[0])
	})

	r.Dispatch("curl", &Help{
		Summary: "Issue arbitrary HTTP requests to the current Vault (for diagnostics)",
		Usage:   "safe curl [OPTIONS] METHOD REL-URI [DATA]",
		Type:    DestructiveCommand,
		Description: `
This is a debugging and diagnostics tool.  You should not need to use
'safe curl' for normal operation or interaction with a Vault.

METHOD must be one of GET, POST, or PUT.

REL-URI is the relative URI (the path component, starting with the first
forward slash) of the resource you wish to access.

DATA should be a JSON string, since almost all of the Vault API handlers
deal exclusively in JSON payloads.  GET requests should not have DATA.
Query string parameters should be appended to REL-URI, instead of being
sent as DATA.
`,
	}, func(command string, args ...string) error {
		rc.Apply()

		if len(args) < 2 {
			r.ExitWithUsage("curl")
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

	if len(args) == 1 && args[0] == "commands" {
		args = []string{"help", "commands"}
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
