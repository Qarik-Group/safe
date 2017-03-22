package main

import (
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

	"github.com/jhunt/go-cli"
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

type Options struct {
	Insecure bool `cli:"-k, --insecure"`
	Version  bool `cli:"-v, --version"`
	Help     bool `cli:"-h, --help"`

	HelpCommand    struct{} `cli:"help"`
	VersionCommand struct{} `cli:"version"`

	/* need option-less commands as well (FIXME) */

	Targets struct{} `cli:"targets"`
	Status  struct{} `cli:"status"`
	Unseal  struct{} `cli:"unseal"`
	Seal    struct{} `cli:"seal"`
	Env     struct{} `cli:"env"`
	Auth    struct{} `cli:"auth, login"`
	Ask     struct{} `cli:"ask"`
	Set     struct{} `cli:"set, write"`
	Paste   struct{} `cli:"paste"`
	Exists  struct{} `cli:"exists, check"`
	Get     struct{} `cli:"get, read, cat"`
	Paths   struct{} `cli:"paths"`

	Tree struct {
		HideLeaves bool `cli:"-d, --hide-leaves"`
	} `cli:"tree"`

	Target struct {
		Interactive bool `cli:"-i, --interactive"`
	} `cli:"target"`

	Delete struct {
		Recurse bool `cli:"-R, -r, --recurse"`
		Force   bool `cli:"-f, --force"`
	} `cli:"delete, rm"`

	Export struct{} `cli:"export"`
	Import struct{} `cli:"import"`

	Move struct {
		Recurse bool `cli:"-R, -r, --recurse"`
		Force   bool `cli:"-f, --force"`
	} `cli:"move, rename, mv"`

	Copy struct {
		Recurse bool `cli:"-R, -r, --recurse"`
		Force   bool `cli:"-f, --force"`
	} `cli:"copy, cp"`

	Gen struct {
		Policy string `cli:"-p, --policy"`
		Length int    `cli:"-l, --length"`
	} `cli:"gen, auto"`

	SSH     struct{} `cli:"ssh"`
	RSA     struct{} `cli:"rsa"`
	DHParam struct{} `cli:"dhparam, dhparams, dh"`
	Prompt  struct{} `cli:"prompt"`
	Vault   struct{} `cli:"vault"`
	Fmt     struct{} `cli:"fmt"`

	PKI struct {
		Init struct {
			TTL     string `cli:"--ttl"`
			Backend string `cli:"--backend"`
		} `cli:"init"`
	} `cli:"pki"`

	CRL struct {
		Backend string `cli:"--backend"`
	} `cli:"crl-pem"`

	CA struct {
		Backend string `cli:"--backend"`
	} `cli:"ca-pem"`

	Cert struct {
		TTL        string `cli:"--ttl"`
		IPSans     string `cli:"--ip-sans"`
		AltNames   string `cli:"--alt-names"`
		CommonName string `cli:"--cn"`
		Role       string `cli:"--role"`
		Backend    string `cli:"--backend"`
		ExcludeCN  bool   `cli:"--exclude-cn-from-sans"`
	} `cli:"cert"`

	Revoke struct {
		Backend string `cli:"--backend"`
	} `cli:"revoke"`

	Curl struct{} `cli:"curl"`

	X509 struct {
		Validate struct {
			CA         bool     `cli:"-A, --ca"`
			SignedBy   string   `cli:"-i, --signed-by"`
			NotRevoked bool     `cli:"-R, --not-revoked"`
			Revoked    bool     `cli:"-r, --revoked"`
			NotExpired bool     `cli:"-E, --not-expired"`
			Expired    bool     `cli:"-e, --expired"`
			Name       []string `cli:"-n, --for"`
			Bits       []int    `cli:"-b, --bits"`
		} `cli:"validate, check"`

		Issue struct {
			CA       bool     `cli:"-A, --ca"`
			Subject  string   `cli:"-s, --subj, --subject"`
			Bits     int      `cli:"-b, --bits"`
			SignedBy string   `cli:"-i, --signed-by"`
			Name     []string `cli:"-n, --name"`
			TTL      string   `cli:"-t, --ttl"`
		} `cli:"issue"`

		Revoke struct {
			SignedBy string `cli:"-i, --signed-by"`
		} `cli:"revoke"`

		CRL struct {
			Renew bool `cli:"--renew"`
		} `cli:"crl"`
	} `cli:"x509"`
}

func main() {
	var opt Options
	opt.Gen.Policy = "a-zA-Z0-9"
	opt.PKI.Init.TTL = "10y"
	opt.PKI.Init.Backend = "pki"
	opt.CRL.Backend = "pki"
	opt.CA.Backend = "pki"
	opt.Cert.Role = "default"
	opt.Cert.Backend = "pki"
	opt.Revoke.Backend = "pki"

	opt.X509.Issue.Bits = 4096
	opt.X509.Issue.TTL = "10y"

	go Signals()

	r := NewRunner()

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
			args = append(args, "commands")
		}
		r.Help(os.Stderr, strings.Join(args, " "))
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
		for name := range cfg.Aliases {
			keys = append(keys, name)
		}

		fmt.Fprintf(os.Stderr, "\n")
		current := fmt.Sprintf("(*) @G{%%-%ds}\t@Y{%%s}@R{%%s}\n", wide)
		other := fmt.Sprintf("    %%-%ds\t%%s@R{%%s}\n", wide)
		sort.Strings(keys)
		for _, name := range keys {
			skip := ""
			if skipverify, ok := cfg.SkipVerify[cfg.Aliases[name]]; ok && skipverify {
				skip = " (insecure)"
			}
			format := other
			if name == cfg.Current {
				format = current
			}
			ansi.Fprintf(os.Stderr, format, name, cfg.Aliases[name], skip)
		}
		fmt.Fprintf(os.Stderr, "\n")
		return nil
	})

	r.Dispatch("target", &Help{
		Summary: "Target a new Vault, or set your current Vault target",
		Usage:   "safe [-k] target [URL] [ALIAS] | safe target -i",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		cfg := rc.Apply()
		skipverify := false
		if os.Getenv("SAFE_SKIP_VERIFY") == "1" {
			skipverify = true
		}

		if opt.Target.Interactive {
			for {
				if len(cfg.Targets) == 0 {
					ansi.Fprintf(os.Stderr, "@R{No Vaults have been targeted yet.}\n\n")
					ansi.Fprintf(os.Stderr, "You will need to target a Vault manually first.\n\n")
					ansi.Fprintf(os.Stderr, "Try something like this:\n")
					ansi.Fprintf(os.Stderr, "     @C{safe target ops https://address.of.your.vault}\n")
					ansi.Fprintf(os.Stderr, "     @C{safe auth (github|token|ldap)}\n")
					ansi.Fprintf(os.Stderr, "\n")
					os.Exit(1)
				}
				r.Execute("targets")
				ansi.Fprintf(os.Stderr, "\n")
				if cfg.Current == "" {
					ansi.Fprintf(os.Stderr, "@R{No Vault currently targeted}\n")
				} else {
					skip := ""
					if !cfg.Verified() {
						skip = " (skipping TLS certificate verification)"
					}
					ansi.Fprintf(os.Stderr, "Currently targeting @C{%s} at @C{%s}@R{%s}\n", cfg.Current, cfg.URL(), skip)
				}

				ansi.Fprintf(os.Stderr, "\nWhich Vault would you like to target?\n")
				t := prompt.Normal("@G{%s> }", cfg.Current)
				err := cfg.SetCurrent(t, skipverify)
				if err != nil {
					ansi.Fprintf(os.Stderr, "@R{%s}\n", err)
					continue
				}
				err = cfg.Write()
				if err != nil {
					return err
				}

				opt.Target.Interactive = false
				return r.Execute("target")
			}
		}
		if len(args) == 0 {
			if cfg.Current == "" {
				ansi.Fprintf(os.Stderr, "@R{No Vault currently targeted}\n")
			} else {
				skip := ""
				if !cfg.Verified() {
					skip = " (skipping TLS certificate verification)"
				}
				ansi.Fprintf(os.Stderr, "Currently targeting @C{%s} at @C{%s}@R{%s}\n", cfg.Current, cfg.URL(), skip)
			}
			return nil
		}
		if len(args) == 1 {
			err := cfg.SetCurrent(args[0], skipverify)
			if err != nil {
				return err
			}
			skip := ""
			if !cfg.Verified() {
				skip = " (skipping TLS certificate verification)"
			}
			ansi.Fprintf(os.Stderr, "Now targeting @C{%s} at @C{%s}@R{%s}\n", cfg.Current, cfg.URL(), skip)
			return cfg.Write()
		}

		if len(args) == 2 {
			var err error
			if strings.HasPrefix(args[1], "http://") || strings.HasPrefix(args[1], "https://") {
				err = cfg.SetTarget(args[0], args[1], skipverify)
			} else {
				err = cfg.SetTarget(args[1], args[0], skipverify)
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
		Summary: "Print the status of the current target's backend nodes",
		Usage:   "safe status",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		rc.Apply()
		v := connect()
		st, err := v.Strongbox()
		if err != nil {

			return fmt.Errorf("%s; are you targeting a `safe' installation?", err)
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
			return fmt.Errorf("%s; are you targeting a `safe' installation?", err)
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
				_, key, err := keyPrompt(fmt.Sprintf("Key #%d", i+1), false, true)
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

	})

	r.Dispatch("ask", &Help{
		Summary: "Create or update an insensitive configuration value",
		Usage:   "safe ask PATH NAME=[VALUE] [NAME ...]",
		Type:    DestructiveCommand,
		Description: `
Update a single path in the Vault with new or updated named attributes.
Any existing name/value pairs not specified on the command-line will
be left alone, with their original values.

You will be prompted to provide (without confirmation) any values that
are omitted. Unlike the 'safe set' and 'safe paste' commands, data entry
is NOT obscured.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		if len(args) < 2 {
			r.ExitWithUsage("ask")
		}
		v := connect()
		path, args := args[0], args[1:]
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		for _, ask := range args {
			k, v, err := keyPrompt(ask, false, false)
			if err != nil {
				return err
			}
			s.Set(k, v)
		}
		return v.Write(path, s)
	})

	writeHelper := func(prompt bool, command string, args ...string) error {
		rc.Apply()
		if len(args) < 2 {
			r.ExitWithUsage(command)
		}
		v := connect()
		path, args := args[0], args[1:]
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		for _, set := range args {
			k, v, err := keyPrompt(set, prompt, true)
			if err != nil {
				return err
			}
			s.Set(k, v)
		}
		return v.Write(path, s)
	}

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
		//writeHelper is defined right above this Dispatch
		return writeHelper(true, "set", args...)
	})

	r.Dispatch("paste", &Help{
		Summary: "Create or update a secret",
		Usage:   "safe paste PATH NAME=[VALUE] [NAME ...]",
		Type:    DestructiveCommand,
		Description: `
Works just like 'safe set', updating a single path in the Vault with new or
updated named attributes.  Any existing name/value pairs not specified on the
command-line will be left alone, with their original values.

You will be prompted to provide any values that are omitted, but unlike the
'safe set' command, you will not be asked to confirm those values.  This makes
sense when you are pasting in credentials from an external password manager
like 1password or Lastpass.
`,
	}, func(command string, args ...string) error {
		//writeHelper is defined right about set, which is defined right about this
		//Dispatch call.
		return writeHelper(false, "paste", args...)
	})

	r.Dispatch("exists", &Help{
		Summary: "Check to see if a secret exists in the Vault",
		Usage:   "safe exists PATH",
		Type:    NonDestructiveCommand,
		Description: `
When you want to see if a secret has been defined, but don't need to know
what its value is, you can use 'safe exists'.  PATH can either be a partial
path (i.e. 'secret/accounts/users/admin') or a fully-qualified path that
incudes a name (like 'secret/accounts/users/admin:username').

'safe exists' does not produce any output, and is suitable for use in scripts.

The process will exit 0 (zero) if PATH exists in the current Vault.
Otherwise, it will exit 1 (one).  If unrelated errors, like network timeouts,
certificate validation failure, etc. occur, they will be printed as well.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		if len(args) != 1 {
			r.ExitWithUsage("exists")
		}
		v := connect()
		_, err := v.Read(args[0])
		if err != nil {
			if vault.IsNotFound(err) {
				os.Exit(1)
			}
			return err
		}
		os.Exit(0)
		return nil
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
	})

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
		opts := vault.TreeOptions{
			UseANSI:    true,
			HideLeaves: opt.Tree.HideLeaves,
		}
		if len(args) == 0 {
			args = append(args, "secret")
		}
		v := connect()
		for _, path := range args {
			tree, err := v.Tree(path, opts)
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

		if len(args) < 1 {
			r.ExitWithUsage("delete")
		}
		v := connect()
		for _, path := range args {
			_, key := vault.ParsePath(path)
			//Ignore -R if path has a key because that makes no sense
			if opt.Delete.Recurse && key == "" {
				if !opt.Delete.Force && !recursively("delete", args...) {
					return nil /* skip this command, process the next */
				}
				if err := v.DeleteTree(path); err != nil && !(vault.IsNotFound(err) && opt.Delete.Force) {
					return err
				}
			} else {
				if err := v.Delete(path); err != nil && !(vault.IsNotFound(err) && opt.Delete.Force) {
					return err
				}
			}
		}
		return nil
	})

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
		if len(args) != 2 {
			r.ExitWithUsage("move")
		}

		v := connect()

		//Don't try to recurse if operating on a key
		// args[0] is the source path. args[1] is the destination path.
		if opt.Move.Recurse && !vault.PathHasKey(args[0]) && !vault.PathHasKey(args[1]) {
			if !opt.Move.Force && !recursively("move", args...) {
				return nil /* skip this command, process the next */
			}
			if err := v.MoveCopyTree(args[0], args[1], v.Move); err != nil && !(vault.IsNotFound(err) && opt.Move.Force) {
				return err
			}
		} else {
			if err := v.Move(args[0], args[1]); err != nil && !(vault.IsNotFound(err) && opt.Move.Force) {
				return err
			}
		}
		return nil
	})

	r.Dispatch("copy", &Help{
		Summary: "Copy a secret from one path to another",
		Usage:   "safe copy [-R] OLD-PATH NEW-PATH",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply()

		if len(args) != 2 {
			r.ExitWithUsage("copy")
		}
		v := connect()

		//Don't try to recurse if operating on a key
		// args[0] is the source path. args[1] is the destination path.
		if opt.Copy.Recurse && !vault.PathHasKey(args[0]) && !vault.PathHasKey(args[1]) {
			if !opt.Copy.Force && !recursively("copy", args...) {
				return nil /* skip this command, process the next */
			}
			if err := v.MoveCopyTree(args[0], args[1], v.Copy); err != nil && !(vault.IsNotFound(err) && opt.Copy.Force) {
				return err
			}
		} else {
			if err := v.Copy(args[0], args[1]); err != nil && !(vault.IsNotFound(err) && opt.Copy.Force) {
				return err
			}
		}
		return nil
	})

	r.Dispatch("gen", &Help{
		Summary: "Generate a random password",
		Usage:   "safe gen [-l <length>] PATH:KEY [PATH:KEY ...]",
		Type:    DestructiveCommand,
		Description: `
LENGTH defaults to 64 characters.

The following options are recognized:

  -p, --policy  Specify a regex character grouping for limiting
                characters used to generate the password (e.g --policy a-z0-9)
`,
	}, func(command string, args ...string) error {
		rc.Apply()

		if len(args) == 0 {
			r.ExitWithUsage("gen")
		}

		length := 64

		if opt.Gen.Length != 0 {
			length = opt.Gen.Length
		} else if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
			length = int(u)
			args = args[1:]
		}

		v := connect()

		for len(args) > 0 {
			var path, key string
			if vault.PathHasKey(args[0]) {
				path, key = vault.ParsePath(args[0])
				args = args[1:]
			} else {
				if len(args) < 2 {
					r.ExitWithUsage("gen")
				}
				path, key = args[0], args[1]
				//If the key looks like a full path with a :key at the end, then the user
				// probably botched the args
				if vault.PathHasKey(key) {
					return fmt.Errorf("For secret `%s` and key `%s`: key cannot contain a key", path, key)
				}
				args = args[2:]
			}
			s, err := v.Read(path)
			if err != nil && !vault.IsNotFound(err) {
				return err
			}
			err = s.Password(key, length, opt.Gen.Policy)
			if err != nil {
				return err
			}

			if err = v.Write(path, s); err != nil {
				return err
			}
		}
		return nil
	})

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
	})

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

	r.Dispatch("pki init", &Help{
		Summary: "Configure the PKI backend on the target Vault",
		Usage:   "safe pki init [OPTIONS]",
		Type:    DestructiveCommand,
		Description: `
Configure your Vault to do PKI via the other safe PKI commands.

You have to run this command first, before you can use the 'cert',
'revoke', 'ca-pem' and 'crl-pem' commands (unless you've already set
up the pki backend on your Vault, in which case, cheers!)

The following options are recognized:

  --ttl          How long the cert should be valid for  (e.g '90d', '10h', etc.)
  --backend      Specify the PKI backend mountpoint to initialize. Defaults to 'pki'.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		v := connect()
		params := make(map[string]interface{})

		inAltUnits := regexp.MustCompile(`^(\d+)([dDyY])$`)
		if match := inAltUnits.FindStringSubmatch(opt.PKI.Init.TTL); len(match) == 3 {
			u, err := strconv.ParseUint(match[1], 10, 16)
			if err != nil {
				return err
			}

			switch match[2] {
			case "d":
				fallthrough
			case "D":
				opt.PKI.Init.TTL = fmt.Sprintf("%dh", u*24)

			case "y":
				fallthrough
			case "Y":
				opt.PKI.Init.TTL = fmt.Sprintf("%dh", u*365*24)

			default:
				return fmt.Errorf("Unrecognized time unit '%s'\n", match[2])
			}
		}
		params["max_lease_ttl"] = opt.PKI.Init.TTL

		mounted, err := v.IsMounted("pki", opt.PKI.Init.Backend)
		if err != nil {
			return err
		}

		/* Mount the PKI backend to `pki/` */
		err = v.Mount("pki", opt.PKI.Init.Backend, params)
		if err != nil {
			return err
		}

		if !mounted {
			/* First Time! */
			common_name := prompt.Normal("@C{Common Name (FQDN)}: ")

			/* Generate the CA certificate */
			m := make(map[string]string)
			m["common_name"] = common_name
			m["ttl"] = opt.PKI.Init.TTL

			err := v.Configure(fmt.Sprintf("%s/root/generate/internal", opt.PKI.Init.Backend), m)
			if err != nil {
				return err
			}

			/* Advertise the CRL / Issuer URLs */
			m = make(map[string]string)
			m["issuing_certificates"] = fmt.Sprintf("%s/v1/%s/ca", v.URL, opt.PKI.Init.Backend)
			m["crl_distribution_points"] = fmt.Sprintf("%s/v1/%s/crl", v.URL, opt.PKI.Init.Backend)

			err = v.Configure(fmt.Sprintf("%s/config/urls", opt.PKI.Init.Backend), m)
			if err != nil {
				return err
			}

			/* Set up a default role, with the same domain as the CA */
			m = make(map[string]string)
			m["allow_any_name"] = "true"
			m["max_ttl"] = opt.PKI.Init.TTL

			err = v.Configure(fmt.Sprintf("%s/roles/default", opt.PKI.Init.Backend), m)
			if err != nil {
				return err
			}
		} else {
			fmt.Printf("The PKI backend `%s` is already initialized\n", opt.PKI.Init.Backend)
		}
		return nil
	})

	r.Dispatch("crl-pem", &Help{
		Summary: "Retrieve the Vault Certificate Revocation List",
		Usage:   "safe crl-pem [OPTIONS] [PATH]",
		Type:    NonDestructiveCommand,
		Description: `
@M{(You must run 'safe pki init' before you can use this command)}

Retrieve the Certificate Revocation List (CRL) from the Vault PKI backend.
This list identifies which of the certificates that Vault has issued have
since been revoked, and should not be trusted, despite their validity.

The CRL will be printed to standard output, as a PEM-encoded value.

If you supply a PATH, the CRL will not be printed, but will be saved at that
path, under the name 'crl-pem'.

The following options are recognized:

  --backend                Specify the PKI backend mountpoint to use. Defaults to 'pki'.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		v := connect()
		pem, err := v.RetrievePem(opt.CRL.Backend, "crl")
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
		Usage:   "safe ca-pem [OPTIONS] [PATH]",
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

The following options are recognized:

  --backend                Specify the PKI backend mountpoint to use. Defaults to 'pki'.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		v := connect()
		pem, err := v.RetrievePem(opt.CA.Backend, "ca")
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
		Usage:   "safe cert [OPTIONS] --cn COMMON_NAME PATH",
		Type:    DestructiveCommand,
		Description: `
@M{(You must run 'safe pki init' before you can use this command)}

Generate a new private key, and then issue a certificate, signed by the
Vault Certificate Authority (CA).

The following options are recognized:

  --ttl                    How long the cert should be valid for
                           (i.e. '90d', '10h', etc.)

  --alt-names              A comma-separated list of alternate DNS
                           names (SANs) to include in the certificate.

  --ip-sans                Comma-separated list of IP addresses to
                           include in the certificate as IP SANs

  --exclude-cn-from-sans   Exclude the certificate's common name (CN)
                           from the Subject Alternate Name list.

  --role                   Specify the PKI Role that will be used
                           to generate this cert.

  --cn                     Specify the CN/Common Name for the Cert

  --backend                Specify the PKI backend mountpoint to use. Defaults to 'pki'.

Once generated, the new private key will be stored under the name 'key',
the certificate will be under 'cert', a combined PEM containing both will
be saved as 'combined', and the certificate serial number under 'serial'.
`,
	}, func(command string, args ...string) error {
		rc.Apply()

		if len(args) != 1 || opt.Cert.CommonName == "" {
			r.ExitWithUsage("cert")
		}

		v := connect()
		params := vault.CertOptions{
			CN:                opt.Cert.CommonName,
			TTL:               opt.Cert.TTL,
			IPSans:            opt.Cert.IPSans,
			AltNames:          opt.Cert.AltNames,
			ExcludeCNFromSans: opt.Cert.ExcludeCN,
		}
		return v.CreateSignedCertificate(opt.Cert.Backend, opt.Cert.Role, args[0], params)
	})

	r.Dispatch("revoke", &Help{
		Summary: "Revoke a Vault-issued Certificate",
		Usage:   "safe revoke [OPTIONS] [PATH | SERIAL]",
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

The following options are recognized:

  --backend                Specify the PKI backend mountpoint to use. Defaults to 'pki'.
`,
	}, func(command string, args ...string) error {
		rc.Apply()
		if len(args) != 1 {
			r.ExitWithUsage("revoke")
		}

		v := connect()
		return v.RevokeCertificate(opt.Revoke.Backend, args[0])
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

	r.Dispatch("x509", &Help{
		Summary: "Issue / Revoke X.509 Certificates and Certificate Authorities",
		Usage:   "safe x509 <command> [OPTIONS]",
		Description: `
x509 provides a handful of sub-commands for issuing, signing and revoking
SSL/TLS X.509 Certificates.  It does not utilize the pki Vault backend;
instead, all certificates and RSA keys are generated by the CLI itself,
and stored wherever you tell it to.

Here are the supported commands:

  @G{x509 issue} [OPTIONS] path/to/store/cert/in

    Issues a new X.509 certificate, which can be either self-signed,
    or signed by another CA certificate, elsewhere in the Vault.
    You can control the subject name, alternate names (DNS, email and
    IP addresses), and TTL/expiry.


  @G{x509 revoke} [OPTIONS] path/to/cert

    Revokes an X.509 certificate that was issues by one of our CAs.


  @G{x509 validate} [OPTIONS] path/to/cert

    Validate a certificate in the Vault, checking to make sure that
    its private and public keys match, checking CA signatories,
    expiration, name applicability, etc.
`,
	}, func(command string, args ...string) error {
		r.Help(os.Stdout, "x509")
		return nil
	})

	r.Dispatch("x509 validate", &Help{
		Summary: "Validate an X.509 Certificate / Private Key",
		Usage:   "safe x509 validate [OPTIONS} path/to/certificate/or/ca",
		Description: `
Certificate validation can be checked in many ways, and this utility
provides most of them, including:

  - Certificate matches private key (default)
  - Certificate was signed by a given CA (--signed-by x)
  - Certificate is not revoked by its CA (--not-revoked)
  - Certificate is not expired (--not-expired)
  - Certificate is valid for a given name / IP / email address (--for)
  - RSA Private Key strength,in bits (--bits)

If any of the selected validations fails, safe will immediately exit
with a non-zero exit code to signal failure.  This can be used in scripts
to check certificates and alter behavior depending on their validity.

If the validations pass, safe will continue on to execute subsequent
sub-commands.

For revocation and expiry checks there are both positive validations (i.e.
this certificate *is* expired) and negative validations (not revoked).
This approach allows you to validate that the certificate you revoked is
actually revoked, while still validating that the certificate and key match,
CA signing constraints, etc.

The following options are recognized:

  -A, --ca            Check that this is a Certificate Authority, with the
                      ability to sign other certifictes.

  -i, --signed-by X   The path to the CA that signed this certificate.
                      safe will check that the CA is the one who signed
                      the certificate, and that the signature is valid.

  -R, --not-revoked   Verify that the certificate has not been revoked
                      by its signing CA.  This makes little sense with
                      self-signed certificates.  Requires the --signed-by
                      option to be specified.

  -r, --revoked       The opposite of --not-revoked; Verify that the CA
                      has revoked the certificate.  Requires --signed-by.

  -E, --not-expired   Check that the certificate is still valid, according
                      to its NotBefore / NotAfter values.

  -e, --expired       Check that the certificate is either not yet valid,
                      or is no longer valid.

  -n, --for N         Check a name / IP / email address against the CN
                      and subject alternate names (of the correct type),
                      to see if the certificate was issued for this name.
                      This can be specified multiple times, in which case
                      all checks must pass for safe to exit zero.

  -b, --bits N        Check that the RSA private key for this certificate
                      has the specified key size (in bits).  This can be
                      specified more than once, in which case any match
                      will pass validation.
`,
	}, func(command string, args ...string) error {
		if len(args) < 1 {
			r.ExitWithUsage("x509 validate")
		}
		if opt.X509.Validate.SignedBy == "" && opt.X509.Validate.Revoked {
			r.ExitWithUsage("x509 validate")
		}
		if opt.X509.Validate.SignedBy == "" && opt.X509.Validate.NotRevoked {
			r.ExitWithUsage("x509 validate")
		}

		rc.Apply()
		v := connect()

		var ca *vault.X509
		if opt.X509.Validate.SignedBy != "" {
			s, err := v.Read(opt.X509.Validate.SignedBy)
			if err != nil {
				return err
			}
			ca, err = s.X509()
			if err != nil {
				return err
			}
		}

		for _, path := range args {
			s, err := v.Read(path)
			if err != nil {
				return err
			}
			cert, err := s.X509()
			if err != nil {
				return err
			}

			if err = cert.Validate(); err != nil {
				return fmt.Errorf("%s failed validation: %s", path, err)
			}

			if opt.X509.Validate.Bits != nil {
				if err = cert.CheckStrength(opt.X509.Validate.Bits...); err != nil {
					return fmt.Errorf("%s failed strength requirement: %s", path, err)
				}
			}

			if opt.X509.Validate.CA && !cert.IsCA() {
				return fmt.Errorf("%s is not a certificate authority", path)
			}

			if opt.X509.Validate.Revoked && !ca.HasRevoked(cert) {
				return fmt.Errorf("%s has not been revoked by %s", path, opt.X509.Validate.SignedBy)
			}
			if opt.X509.Validate.NotRevoked && ca.HasRevoked(cert) {
				return fmt.Errorf("%s has been revoked by %s", path, opt.X509.Validate.SignedBy)
			}

			if opt.X509.Validate.Expired && !cert.Expired() {
				return fmt.Errorf("%s has not yet expired", path)
			}
			if opt.X509.Validate.NotExpired && cert.Expired() {
				return fmt.Errorf("%s has expired", path)
			}

			if _, err = cert.ValidFor(opt.X509.Validate.Name...); err != nil {
				return err
			}

			ansi.Printf("@G{%s} checks out.\n", path)
		}

		return nil
	})

	r.Dispatch("x509 issue", &Help{
		Summary: "Issue X.509 Certificates and Certificate Authorities",
		Usage:   "safe x509 issue [OPTIONS] --name cn.example.com path/to/certificate",
		Description: `
Issue a new X.509 Certificate

The following options are recognized:

  -A, --ca          This certificate is a CA, and can
                    sign other certificates.

  -s, --subject     The subject name for this certificate.
                    i.e. /cn=www.example.com/c=us/st=ny...
                    If not specified, the first '--name'
                    will be used as a lone CN=...

  -i, --signed-by   Path in the Vault where the CA certificate
                    (and signing key) can be found.
                    Without this option, 'x509 issue' creates
                    self-signed certificates.

  -n, --name        Subject Alternate Name(s) for this
                    certificate.  These can be domain names,
                    IP addresses or email address -- safe will
                    figure out how to properly encode them.
                    Can (and probably should) be specified
                    more than once.

  -b, --bits N      RSA key strength, in bits.  The only valid
                    arguments are 1024 (highly discouraged),
                    2048 and 4096.  Defaults to 4096.

  -t, --ttl         How long the new certificate will be valid
                    for.  Specified in units h (hours), m (months)
                    d (days) or y (years).  1m = 30d and 1y = 365d
                    Defaults to 10y
	`,
	}, func(command string, args ...string) error {
		rc.Apply()

		var ca *vault.X509

		if len(args) != 1 || len(opt.X509.Issue.Name) == 0 {
			r.ExitWithUsage("x509 issue")
		}

		if opt.X509.Issue.Subject == "" {
			opt.X509.Issue.Subject = fmt.Sprintf("CN=%s", opt.X509.Issue.Name[0])
		}

		v := connect()
		if opt.X509.Issue.SignedBy != "" {
			secret, err := v.Read(opt.X509.Issue.SignedBy)
			if err != nil {
				return err
			}

			ca, err = secret.X509()
			if err != nil {
				return err
			}
		}

		cert, err := vault.NewCertificate(opt.X509.Issue.Subject, opt.X509.Issue.Name, opt.X509.Issue.Bits)
		if err != nil {
			return err
		}

		if opt.X509.Issue.CA {
			cert.MakeCA(1)
		}

		ttl, err := duration(opt.X509.Issue.TTL)
		if err != nil {
			return err
		}
		if ca == nil {
			if err := cert.Sign(cert, ttl); err != nil {
				return err
			}
		} else {
			if err := ca.Sign(cert, ttl); err != nil {
				return err
			}

			s, err := ca.Secret()
			if err != nil {
				return err
			}
			err = v.Write(opt.X509.Issue.SignedBy, s)
			if err != nil {
				return err
			}
		}

		s, err := cert.Secret()
		if err != nil {
			return err
		}
		err = v.Write(args[0], s)
		if err != nil {
			return err
		}

		return nil
	})

	r.Dispatch("x509 revoke", &Help{
		Summary: "Revoke X.509 Certificates and Certificate Authorities",
		Usage:   "safe x509 revoke [OPTIONS] path/to/certificate",
		Description: `
Revoke an X.509 Certificate via its Certificate Authority

The following options are recognized:

  -i, --signed-by   Path in the Vault where the CA certificate that
                    signed the certificate to revoke resides.
`,
	}, func(command string, args ...string) error {
		if opt.X509.Revoke.SignedBy == "" || len(args) != 1 {
			r.ExitWithUsage("x509 revoke")
		}

		rc.Apply()
		v := connect()

		/* find the CA */
		s, err := v.Read(opt.X509.Revoke.SignedBy)
		if err != nil {
			return err
		}
		ca, err := s.X509()
		if err != nil {
			return err
		}

		/* find the Certificate */
		s, err = v.Read(args[0])
		if err != nil {
			return err
		}
		cert, err := s.X509()
		if err != nil {
			return err
		}

		/* revoke the Certificate */
		/* FIXME make sure the CA signed this cert */
		ca.Revoke(cert)
		s, err = ca.Secret()
		if err != nil {
			return err
		}

		err = v.Write(opt.X509.Revoke.SignedBy, s)
		if err != nil {
			return err
		}

		return nil
	})

	r.Dispatch("x509 crl", &Help{
		Summary: "Manage a X.509 Certificate Authority Revocation List",
		Usage:   "safe x509 crl --renew path",
		Description: `
Each X.509 Certificate Authority (especially those generated by
'safe issue --ca') carries with a list of certificates it has revoked,
by certificate serial number.  This command lets you manage that CRL.

Currently, only the --renew option is supported, and it is required:

  --renew           Sign and update the validity dates of the CRL,
                    without modifying the list of revoked certificates.
`,
	}, func(command string, args ...string) error {
		if !opt.X509.CRL.Renew || len(args) != 1 {
			r.ExitWithUsage("x509 crl")
		}

		rc.Apply()
		v := connect()

		s, err := v.Read(args[0])
		if err != nil {
			return err
		}
		ca, err := s.X509()
		if err != nil {
			return err
		}

		if !ca.IsCA() {
			return fmt.Errorf("%s is not a certificate authority", args[0])
		}

		/* simply re-saving the CA X509 object regens the CRL */
		s, err = ca.Secret()
		if err != nil {
			return err
		}
		err = v.Write(args[0], s)
		if err != nil {
			return err
		}

		return nil
	})

	p, err := cli.NewParser(&opt, os.Args[1:])
	if err != nil {
		ansi.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}

	if opt.Version {
		r.Execute("version")
		return
	}
	if opt.Help { //-h was given as a global arg
		r.Execute("help")
		return
	}

	for p.Next() {
		if opt.Version {
			r.Execute("version")
			return
		}

		if p.Command == "" { //No recognized command was found
			r.Execute("help")
			return
		}

		if opt.Help { // -h or --help was given after a command
			r.Execute("help", p.Command)
			continue
		}

		os.Unsetenv("SAFE_SKIP_VERIFY")
		if opt.Insecure {
			os.Setenv("VAULT_SKIP_VERIFY", "1")
			os.Setenv("SAFE_SKIP_VERIFY", "1")
		}

		err = r.Execute(p.Command, p.Args...)
		if err != nil {
			if strings.HasPrefix(err.Error(), "USAGE") {
				ansi.Fprintf(os.Stderr, "@Y{%s}\n", err)
			} else {
				ansi.Fprintf(os.Stderr, "@R{!! %s}\n", err)
			}
			os.Exit(1)
		}
	}

	//If there were no args given, the above loop that would try to give help
	// doesn't execute at all, so we catch it here.
	if p.Command == "" {
		r.Execute("help")
	}

	if err = p.Error(); err != nil {
		ansi.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}
}

func recursively(cmd string, args ...string) bool {
	y := prompt.Normal("Recursively %s %s (y/n) ", cmd, strings.Join(args, " "))
	y = strings.TrimSpace(y)
	return y == "y" || y == "yes"
}
