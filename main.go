package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http/httputil"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	fmt "github.com/jhunt/go-ansi"
	"github.com/jhunt/go-cli"
	"gopkg.in/yaml.v2"

	"github.com/starkandwayne/safe/auth"
	"github.com/starkandwayne/safe/prompt"
	"github.com/starkandwayne/safe/rc"
	"github.com/starkandwayne/safe/vault"
)

var Version string

func connect(auth bool) *vault.Vault {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		fmt.Fprintf(os.Stderr, "@R{You are not targeting a Vault.}\n")
		fmt.Fprintf(os.Stderr, "Try @C{safe target http://your-vault alias}\n")
		fmt.Fprintf(os.Stderr, " or @C{safe target alias}\n")
		os.Exit(1)
	}

	if auth && os.Getenv("VAULT_TOKEN") == "" {
		fmt.Fprintf(os.Stderr, "@R{You are not authenticated to a Vault.}\n")
		fmt.Fprintf(os.Stderr, "Try @C{safe auth ldap}\n")
		fmt.Fprintf(os.Stderr, " or @C{safe auth github}\n")
		fmt.Fprintf(os.Stderr, " or @C{safe auth token}\n")
		fmt.Fprintf(os.Stderr, " or @C{safe auth userpass}\n")
		os.Exit(1)
	}

	v, err := vault.NewVault(addr, os.Getenv("VAULT_TOKEN"), auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}
	return v
}

type Options struct {
	Insecure     bool `cli:"-k, --insecure"`
	Version      bool `cli:"-v, --version"`
	Help         bool `cli:"-h, --help"`
	Clobber      bool `cli:"--clobber, --no-clobber"`
	SkipIfExists bool
	Quiet        bool `cli:"--quiet"`

	UseTarget string `cli:"-T, --target"`

	HelpCommand    struct{} `cli:"help"`
	VersionCommand struct{} `cli:"version"`

	Targets struct{} `cli:"targets"`
	Status  struct{} `cli:"status"`
	Unseal  struct{} `cli:"unseal"`
	Seal    struct{} `cli:"seal"`
	Env     struct{} `cli:"env"`
	Auth    struct{} `cli:"auth, login"`
	Renew   struct{} `cli:"renew"`
	Ask     struct{} `cli:"ask"`
	Set     struct{} `cli:"set, write"`
	Paste   struct{} `cli:"paste"`
	Exists  struct{} `cli:"exists, check"`

	Init struct {
		Single    bool `cli:"-s, --single"`
		NKeys     int  `cli:"--keys"`
		Threshold int  `cli:"--threshold"`
		JSON      bool `cli:"--json"`
		Sealed    bool `cli:"--sealed"`
	} `cli:"init"`

	Rekey struct {
		NKeys     int      `cli:"--keys, --num-unseal-keys"`
		Threshold int      `cli:"--threshold, --keys-to-unseal"`
		GPG       []string `cli:"--gpg"`
	} `cli:"rekey"`

	Get struct {
		KeysOnly bool `cli:"--keys"`
		Yaml     bool `cli:"--yaml"`
	} `cli:"get, read, cat"`

	List struct {
		Single bool `cli:"-1"`
	} `cli:"ls"`

	Paths struct {
		ShowKeys bool `cli:"--keys"`
	} `cli:"paths"`

	Tree struct {
		ShowKeys   bool `cli:"--keys"`
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
	Vault   struct{} `cli:"vault!"`
	Fmt     struct{} `cli:"fmt"`

	Curl struct {
		DataOnly bool `cli:"--data-only"`
	} `cli:"curl"`

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
			KeyUsage []string `cli:"-u, --key-usage"`
		} `cli:"issue"`

		Revoke struct {
			SignedBy string `cli:"-i, --signed-by"`
		} `cli:"revoke"`

		Show struct {
		} `cli:"show"`

		CRL struct {
			Renew bool `cli:"--renew"`
		} `cli:"crl"`
	} `cli:"x509"`
}

func main() {
	var opt Options
	opt.Gen.Policy = "a-zA-Z0-9"

	opt.Clobber = true

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

		if opt.UseTarget != "" {
			fmt.Fprintf(os.Stderr, "@Y{Specifying --target to the targets command makes no sense; ignoring...}\n")
		}

		cfg := rc.Apply(opt.UseTarget)
		wide := 0
		keys := make([]string, 0)
		for name := range cfg.Vaults {
			keys = append(keys, name)
			if len(name) > wide {
				wide = len(name)
			}
		}

		current_fmt := fmt.Sprintf("(*) @G{%%-%ds}\t@R{%%s} @Y{%%s}\n", wide)
		other_fmt := fmt.Sprintf("    %%-%ds\t@R{%%s} %%s\n", wide)
		has_current := ""
		if cfg.Current != "" {
			has_current = " - current target indicated with a (*)"
		}

		fmt.Fprintf(os.Stderr, "\nKnown Vault targets%s:\n", has_current)
		sort.Strings(keys)
		for _, name := range keys {
			t := cfg.Vaults[name]
			skip := "           "
			if t.SkipVerify {
				skip = " (noverify)"
			} else if strings.HasPrefix(t.URL, "http:") {
				skip = " (insecure)"
			}
			format := other_fmt
			if name == cfg.Current {
				format = current_fmt
			}
			fmt.Fprintf(os.Stderr, format, name, skip, t.URL)
		}
		fmt.Fprintf(os.Stderr, "\n")
		return nil
	})

	r.Dispatch("target", &Help{
		Summary: "Target a new Vault, or set your current Vault target",
		Usage:   "safe [-k] target [URL] [ALIAS] | safe target -i",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		cfg := rc.Apply(opt.UseTarget)
		skipverify := false
		if os.Getenv("SAFE_SKIP_VERIFY") == "1" {
			skipverify = true
		}

		if opt.UseTarget != "" {
			fmt.Fprintf(os.Stderr, "@Y{Specifying --target to the target command makes no sense; ignoring...}\n")
		}

		if opt.Target.Interactive {
			for {
				if len(cfg.Vaults) == 0 {
					fmt.Fprintf(os.Stderr, "@R{No Vaults have been targeted yet.}\n\n")
					fmt.Fprintf(os.Stderr, "You will need to target a Vault manually first.\n\n")
					fmt.Fprintf(os.Stderr, "Try something like this:\n")
					fmt.Fprintf(os.Stderr, "     @C{safe target ops https://address.of.your.vault}\n")
					fmt.Fprintf(os.Stderr, "     @C{safe auth (github|token|ldap|userpass)}\n")
					fmt.Fprintf(os.Stderr, "\n")
					os.Exit(1)
				}
				r.Execute("targets")

				fmt.Fprintf(os.Stderr, "Which Vault would you like to target?\n")
				t := prompt.Normal("@G{> }")
				err := cfg.SetCurrent(t, skipverify)
				if err != nil {
					fmt.Fprintf(os.Stderr, "@R{%s}\n", err)
					continue
				}
				err = cfg.Write()
				if err != nil {
					return err
				}
				if !opt.Quiet {
					skip := ""
					if !cfg.Verified() {
						skip = " (skipping TLS certificate verification)"
					}
					fmt.Fprintf(os.Stderr, "Now targeting @C{%s} at @C{%s}@R{%s}\n\n", cfg.Current, cfg.URL(), skip)
				}
				return nil
			}
		}
		if len(args) == 0 {
			if !opt.Quiet {
				if cfg.Current == "" {
					fmt.Fprintf(os.Stderr, "@R{No Vault currently targeted}\n")
				} else {
					skip := ""
					if !cfg.Verified() {
						skip = " (skipping TLS certificate verification)"
					}
					fmt.Fprintf(os.Stderr, "Currently targeting @C{%s} at @C{%s}@R{%s}\n\n", cfg.Current, cfg.URL(), skip)
				}
			}
			return nil
		}
		if len(args) == 1 {
			err := cfg.SetCurrent(args[0], skipverify)
			if err != nil {
				return err
			}
			if !opt.Quiet {
				skip := ""
				if !cfg.Verified() {
					skip = " (skipping TLS certificate verification)"
				}
				fmt.Fprintf(os.Stderr, "Now targeting @C{%s} at @C{%s}@R{%s}\n\n", cfg.Current, cfg.URL(), skip)
			}
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
			if !opt.Quiet {
				fmt.Fprintf(os.Stderr, "Now targeting @C{%s} at @C{%s}\n\n", cfg.Current, cfg.URL())
			}
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
		rc.Apply(opt.UseTarget)
		v := connect(false)
		st, err := v.Strongbox()
		if err != nil {
			return fmt.Errorf("%s; are you targeting a `safe' installation?", err)
		}

		for addr, state := range st {
			if state == "sealed" {
				fmt.Printf("@R{%s is sealed}\n", addr)
			} else {
				fmt.Printf("@G{%s is unsealed}\n", addr)
			}
		}
		return nil
	})

	r.Dispatch("init", &Help{
		Summary: "Initialize a new vault",
		Usage:   "safe init [--keys #] [--threshold #] [--single] [--json] [--sealed]",
		Description: `
Initializes a brand new Vault backend, generating new seal keys, and an
initial root token.  This information will be printed out, so that you
can save it somewhere secure (encrypted drive, password manager, etc.)

By default, Vault is initialized with 5 unseal keys, 3 of which are
required to unseal the Vault after a restart.  You can adjust this via
the --keys and --threshold options.  The --single option is a shortcut
for specifying a single key and a threshold of 1.

Once the Vault is initialized, safe will unseal it automatically, using
the newly minted seal keys, unless you pass it the --sealed option.
The root token will also be stored in the ~/.saferc file, saving you the
trouble of calling 'safe auth token' yourself.

The --json flag causes 'safe init' to print out the seal keys and initial
root token in a machine-friendly JSON format, that looks like this:

    {
      "root_token": "05f28556-db0a-f76f-3c26-40de20f28cee"
      "seal_keys": [
        "jDuvcXg7s4QnjHjwN9ydSaFtoMj8YZWrO8hRFWT2PoqT",
        "XiE5cq0+AsUcK8EK8GomCsMdylixwWa8tM2L991OHcry",
        "F9NbroyispQTCMHBWBD5+lYxMEms5hntwsrxcdZx1+3w",
        "3scP3yIdfLv9mr0YbxZRClpPNSf5ohVpWmxrpRQ/a9JM",
        "NosOaAjZzvcdHKBvtaqLDRwWSG6/XkLwgZHvnIvAhOC5"
      ]
    }

This can be used to automate the setup of Vaults for test/dev purposes,
which can be quite handy.
`,
		Type: AdministrativeCommand,
	}, func(command string, args ...string) error {
		cfg := rc.Apply(opt.UseTarget)
		v := connect(false)

		if opt.Init.NKeys == 0 {
			opt.Init.NKeys = 5
		}
		if opt.Init.Threshold == 0 {
			if opt.Init.NKeys > 3 {
				opt.Init.Threshold = opt.Init.NKeys - 2
			} else {
				opt.Init.Threshold = opt.Init.NKeys
			}
		}

		if opt.Init.Single {
			opt.Init.NKeys = 1
			opt.Init.Threshold = 1
		}

		/* initialize the vault */
		keys, token, err := v.Init(opt.Init.NKeys, opt.Init.Threshold)
		if err != nil {
			return err
		}

		if token == "" {
			panic("token was nil")
		}

		/* auth with the new root token, transparently */
		cfg.SetToken(token)
		if err := cfg.Write(); err != nil {
			return err
		}
		os.Setenv("VAULT_TOKEN", token)
		v = connect(true)

		/* unseal if we weren't called with --sealed */
		if !opt.Init.Sealed {
			if st, err := v.Strongbox(); err == nil {
				for addr := range st {
					v.URL = addr
					if err := v.Unseal(keys); err != nil {
						fmt.Fprintf(os.Stderr, "!!! unable to unseal newly-initialized vault (at %s): %s\n", addr, err)
					}
				}

			} else {
				if err := v.Unseal(keys); err != nil {
					fmt.Fprintf(os.Stderr, "!! unable to unseal newly-initialized vault: %s\n", err)
				}
			}

			/* write secret/handshake, just for fun */
			s := vault.NewSecret()
			s.Set("knock", "knock", false)
			v.Write("secret/handshake", s)
		}

		/* be nice to the machines and machine-like intelligences */
		if opt.Init.JSON {
			out := struct {
				Keys  []string `json:"seal_keys"`
				Token string   `json:"root_token"`
			}{
				Keys:  keys,
				Token: token,
			}

			b, err := json.MarshalIndent(&out, "", "  ")
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", string(b))
			return nil
		}

		for i, key := range keys {
			fmt.Printf("Unseal Key #%d: @G{%s}\n", i+1, key)
		}
		fmt.Printf("Initial Root Token: @M{%s}\n", token)
		fmt.Printf("\n")
		if opt.Init.NKeys == 1 {
			fmt.Printf("Vault initialized with a single key. Please securely distribute it.\n")
			fmt.Printf("When the Vault is re-sealed, restarted, or stopped, you must provide\n")
			fmt.Printf("this key to unseal it again.\n")
			fmt.Printf("\n")
			fmt.Printf("Vault does not store the master key. Without the above unseal key,\n")
			fmt.Printf("your Vault will remain permanently sealed.\n")

		} else if opt.Init.NKeys == opt.Init.Threshold {
			fmt.Printf("Vault initialized with %d keys. Please securely distribute the\n", opt.Init.NKeys)
			fmt.Printf("above keys. When the Vault is re-sealed, restarted, or stopped,\n")
			fmt.Printf("you must provide all of these keys to unseal it again.\n")
			fmt.Printf("\n")
			fmt.Printf("Vault does not store the master key. Without all %d of the keys,\n", opt.Init.Threshold)
			fmt.Printf("your Vault will remain permanently sealed.\n")

		} else {
			fmt.Printf("Vault initialized with %d keys and a key threshold of %d. Please\n", opt.Init.NKeys, opt.Init.Threshold)
			fmt.Printf("securely distribute the above keys. When the Vault is re-sealed,\n")
			fmt.Printf("restarted, or stopped, you must provide at least %d of these keys\n", opt.Init.Threshold)
			fmt.Printf("to unseal it again.\n")
			fmt.Printf("\n")
			fmt.Printf("Vault does not store the master key. Without at least %d keys,\n", opt.Init.Threshold)
			fmt.Printf("your Vault will remain permanently sealed.\n")
		}

		fmt.Printf("\n")
		if !opt.Init.Sealed {
			fmt.Printf("safe has unsealed the Vault for you, and written a test value\n")
			fmt.Printf("at @C{secret/handshake}.\n")
		} else {
			fmt.Printf("Your Vault has been left sealed.\n")
		}
		fmt.Printf("\n")
		fmt.Printf("You have been automatically authenticated to the Vault with the\n")
		fmt.Printf("initial root token.  Be safe out there!\n")
		fmt.Printf("\n")

		return nil
	})

	r.Dispatch("unseal", &Help{
		Summary: "Unseal the current target",
		Usage:   "safe unseal",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)
		v := connect(false)
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
			fmt.Printf("@C{all vaults are already unsealed!}\n")
		} else {
			fmt.Printf("You need %d key(s) to unseal the vaults.\n\n", nkeys)
			keys := make([]string, nkeys)

			for i := 0; i < nkeys; i++ {
				keys[i] = pr(fmt.Sprintf("Key #%d", i+1), false, true)
			}

			for addr, state := range st {
				if state == "sealed" {
					fmt.Printf("unsealing @G{%s}...\n", addr)
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
		rc.Apply(opt.UseTarget)
		v := connect(true)
		st, err := v.Strongbox()
		if err != nil {
			return fmt.Errorf("%s; are you targeting a `safe' installation?", err)
		}

		n := 0
		for _, state := range st {
			if state == "unsealed" {
				n++
			}
		}

		if n == 0 {
			fmt.Printf("@C{all vaults are already sealed!}\n")
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
						fmt.Printf("sealed @G{%s}...\n", addr)
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
		rc.Apply(opt.UseTarget)
		fmt.Fprintf(os.Stderr, "  @B{VAULT_ADDR}  @G{%s}\n", os.Getenv("VAULT_ADDR"))
		fmt.Fprintf(os.Stderr, "  @B{VAULT_TOKEN} @G{%s}\n", os.Getenv("VAULT_TOKEN"))
		return nil
	})

	r.Dispatch("auth", &Help{
		Summary: "Authenticate to the current target",
		Usage:   "safe auth (token|github|ldap|userpass)",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		cfg := rc.Apply(opt.UseTarget)

		method := "token"
		if len(args) > 0 {
			method = args[0]
			args = args[1:]
		}

		var token string
		var err error

		fmt.Fprintf(os.Stderr, "Authenticating against @C{%s} at @C{%s}\n", cfg.Current, cfg.URL())
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

		case "userpass":
			token, err = auth.UserPass(os.Getenv("VAULT_ADDR"))
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

	r.Dispatch("renew", &Help{
		Summary: "Renew one or more authentication tokens",
		Usage:   "safe renew [all]\n",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		if len(args) > 0 {
			if len(args) != 1 || args[0] != "all" {
				r.ExitWithUsage("renew")
			}
			cfg := rc.Apply("")
			failed := 0
			for vault := range cfg.Vaults {
				rc.Apply(vault)
				if os.Getenv("VAULT_TOKEN") == "" {
					fmt.Printf("skipping @C{%s} - no token found.\n", vault)
					continue
				}
				fmt.Printf("renewing token against @C{%s}...\n", vault)
				v := connect(true)
				if err := v.RenewLease(); err != nil {
					fmt.Fprintf(os.Stderr, "@R{failed to renew token against %s: %s}\n", vault, err)
					failed++
				}
			}
			if failed > 0 {
				return fmt.Errorf("failed to renew %d token(s).", failed)
			}
			return nil

		} else {
			rc.Apply(opt.UseTarget)
			v := connect(true)
			if err := v.RenewLease(); err != nil {
				return err
			}
		}
		return nil
	})

	writeHelper := func(prompt bool, insecure bool, command string, args ...string) error {
		rc.Apply(opt.UseTarget)
		if len(args) < 2 {
			r.ExitWithUsage(command)
		}
		v := connect(true)
		path, args := args[0], args[1:]
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		exists := (err == nil)
		clobberKeys := []string{}
		for _, arg := range args {
			k, v, missing, err := parseKeyVal(arg, opt.Quiet)
			if err != nil {
				return err
			}
			if opt.SkipIfExists && exists && s.Has(k) {
				clobberKeys = append(clobberKeys, k)
				continue
			}
			// realize that we're going to fail, and don't prompt the user for any info
			if len(clobberKeys) > 0 {
				continue
			}
			if missing {
				v = pr(k, prompt, insecure)
			}
			if err != nil {
				return err
			}
			err = s.Set(k, v, opt.SkipIfExists)
			if err != nil {
				return err
			}
		}
		if len(clobberKeys) > 0 {
			if !opt.Quiet {
				fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to update} @C{%s}@R{, as the following keys would be clobbered:} @C{%s}\n",
					path, strings.Join(clobberKeys, ", "))
			}
			return nil
		}
		return v.Write(path, s)
	}

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
		return writeHelper(false, false, "ask", args...)
	})

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
		return writeHelper(true, true, "set", args...)
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
		//Dispatch call.
		return writeHelper(false, true, "paste", args...)
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
		rc.Apply(opt.UseTarget)
		if len(args) != 1 {
			r.ExitWithUsage("exists")
		}
		v := connect(true)
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
		Summary: "Retrieve the key/value pairs (or just keys) of one or more paths",
		Usage:   "safe get [--keys] [--yaml] PATH [PATH ...]",
		Description: `
Allows you to retrieve one or more values stored in the given secret, or just the
valid keys.  It operates in the following modes:

If a single path is specified that does not include a :key suffix, the output
will be the key:value pairs for that secret, in YAML format.  It will not include
the specified path as the base hash key; instead, it will be output as a comment
behind the document indicator (---).  To force it to include the full path as
the root key, specify --yaml.

If a single path is specified including the :key suffix, the single value of that
path:key will be output in string format.  To force the use of the fully qualified
{path: {key: value}} output in YAML format, use --yaml option.

If a single path is specified along with --keys, the list of keys for that given
path will be returned.  If that path does not contain any secrets (ie its not a
leaf node or does not exist), it will output nothing, but will not error.  If a
specific key is specified, it will output only that key if it exists, otherwise
nothing. You can specify --yaml to force YAML output.

If you specify more than one path, output is forced to be YAML, with the primary
hash key being the requested path (not including the key if provided).  If --keys
is specified, the next level will contain the keys found under that path; if the
path included a key component, only the specified keys will be present.  Without
the --keys option, the key: values for each found (or requested) key for the path
will be output.

If an invalid key or path is requested, an error will be output and nothing else
unless the --keys option is specified.  In that case, the error will be displayed
as a warning, but the output will be provided with an empty array for missing
paths/keys.
`,
		Type: NonDestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)
		if len(args) < 1 {
			r.ExitWithUsage("get")
		}

		v := connect(true)

		// Recessive case of one path
		if len(args) == 1 && !opt.Get.Yaml {
			s, err := v.Read(args[0])
			if err != nil {
				return err
			}

			if opt.Get.KeysOnly {
				keys := s.Keys()
				for _, key := range keys {
					fmt.Printf("%s\n", key)
				}
			} else if _, key := vault.ParsePath(args[0]); key != "" {
				value, err := s.SingleValue()
				if err != nil {
					return err
				}
				fmt.Printf("%s\n", value)
			} else {
				fmt.Printf("--- # %s\n%s\n", args[0], s.YAML())
			}
			return nil
		}

		// Track errors, paths, keys, values
		errs := make([]error, 0)
		results := make(map[string]map[string]string, 0)
		missing_keys := make(map[string][]string)
		for _, path := range args {
			p, k := vault.ParsePath(path)
			s, err := v.Read(path)

			// Check if the desired path[:key] is found
			if err != nil {
				errs = append(errs, err)
				if k != "" {
					if _, ok := missing_keys[p]; !ok {
						missing_keys[p] = make([]string, 0)
					}
					missing_keys[p] = append(missing_keys[p], k)
				}
				continue
			}

			if _, ok := results[p]; !ok {
				results[p] = make(map[string]string, 0)
			}
			for _, key := range s.Keys() {
				results[p][key] = s.Get(key)
			}
		}

		// Handle any errors encountered.  Warn for key request, return error otherwise
		var err error
		num_errs := len(errs)
		if num_errs == 1 {
			err = errs[0]
		} else if len(errs) > 1 {
			errStr := "Multiple errors found:"
			for _, err := range errs {
				errStr += fmt.Sprintf("\n   - %s", err)
			}
			err = errors.New(errStr)
		}
		if num_errs > 0 {
			if opt.Get.KeysOnly {
				fmt.Fprintf(os.Stderr, "@y{WARNING:} %s\n", err)
			} else {
				return err
			}
		}

		// Now that we've collected/collated all the data, format and print it
		fmt.Printf("---\n")
		if opt.Get.KeysOnly {
			printed_paths := make(map[string]bool, 0)
			for _, path := range args {
				p, _ := vault.ParsePath(path)
				if printed, _ := printed_paths[p]; printed {
					continue
				}
				printed_paths[p] = true
				result, ok := results[p]
				if !ok {
					yml, _ := yaml.Marshal(map[string][]string{p: []string{}})
					fmt.Printf("%s", string(yml))
				} else {
					found_keys := reflect.ValueOf(result).MapKeys()
					str_keys := make([]string, len(found_keys))
					for i := 0; i < len(found_keys); i++ {
						str_keys[i] = found_keys[i].String()
					}
					sort.Strings(str_keys)
					yml, _ := yaml.Marshal(map[string][]string{p: str_keys})
					fmt.Printf("%s\n", string(yml))
				}
			}
		} else {
			yml, _ := yaml.Marshal(results)
			fmt.Printf("%s\n", string(yml))
		}
		return nil
	})

	r.Dispatch("ls", &Help{
		Summary: "Print the keys and sub-directories at one or more paths",
		Usage:   "safe ls [-1] [PATH ...]",
		Type:    NonDestructiveCommand,
		Description: `
`,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)
		v := connect(true)
		if len(args) == 0 {
			secrets, err := v.Mounts("secret")
			if err != nil {
				return err
			}
			kvs, err := v.Mounts("kv")
			if err != nil {
				return err
			}

			secrets = append(secrets, kvs...)
			sort.Strings(secrets)

			if opt.List.Single {
				for _, path := range secrets {
					fmt.Printf("@B{%s/}\n", path)
				}
			} else {
				for _, path := range secrets {
					fmt.Printf("@B{%s/}  ", path)
				}
				fmt.Printf("\n")
			}
			return nil
		}
		for _, path := range args {
			paths, err := v.List(path)
			if err != nil {
				return err
			}

			if len(args) != 1 {
				fmt.Printf("@C{%s}:\n", path)
			}
			if opt.List.Single {
				for _, s := range paths {
					if strings.HasSuffix(s, "/") {
						fmt.Printf("@B{%s}\n", s)
					} else {
						fmt.Printf("@G{%s}\n", s)
					}
				}
			} else {
				for _, s := range paths {
					if strings.HasSuffix(s, "/") {
						fmt.Printf("@B{%s}  ", s)
					} else {
						fmt.Printf("@G{%s}  ", s)
					}
				}
				fmt.Printf("\n")
			}
			if len(args) != 1 {
				fmt.Printf("\n")
			}
		}
		return nil
	})

	r.Dispatch("tree", &Help{
		Summary: "Print a tree listing of one or more paths",
		Usage:   "safe tree [-d|--keys] [PATH ...]",
		Type:    NonDestructiveCommand,
		Description: `
Walks the hierarchy of secrets stored underneath a given path, listing all
reachable name/value pairs.  If '-d' is given, only the containing folders
will be printed; this more concise output can be useful when you're trying
to get your bearings.
`,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)
		opts := vault.TreeOptions{
			UseANSI:    true,
			HideLeaves: opt.Tree.HideLeaves,
			ShowKeys:   opt.Tree.ShowKeys,
		}
		if opt.Tree.HideLeaves && opt.Tree.ShowKeys {
			return fmt.Errorf("Cannot specify both -d and --keys at the same time")
		}
		if len(args) == 0 {
			args = append(args, "secret")
		}
		r1, _ := regexp.Compile("^ ")
		r2, _ := regexp.Compile("^└")
		v := connect(true)
		for i, path := range args {
			tree, err := v.Tree(path, opts)
			if err != nil {
				return err
			}
			lines := strings.Split(tree.Draw(), "\n")
			if i > 0 {
				lines = lines[1:] // Drop root '.' from subsequent paths
			}
			if i < len(args)-1 {
				lines = lines[:len(lines)-1]
			}
			for _, line := range lines {
				if i < len(args)-1 {
					line = r1.ReplaceAllString(r2.ReplaceAllString(line, "├"), "│")
				}
				fmt.Printf("%s\n", line)
			}
		}
		return nil
	})

	r.Dispatch("paths", &Help{
		Summary: "Print all of the known paths, one per line",
		Usage:   "safe paths [--keys] PATH [PATH ...]",
		Type:    NonDestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)
		if len(args) < 1 {
			args = append(args, "secret")
		}
		v := connect(true)
		for _, path := range args {
			tree, err := v.Tree(path, vault.TreeOptions{
				UseANSI:      false,
				ShowKeys:     opt.Paths.ShowKeys,
				StripSlashes: true,
			})
			if err != nil {
				return err
			}

			for _, segs := range tree.PathSegments() {
				var has_key bool
				var key string
				if segs[len(segs)-1][0] == ':' {
					has_key = true
					key, segs = segs[len(segs)-1], segs[:len(segs)-1]
				}
				path := strings.Join(segs, "/")
				if has_key {
					path = fmt.Sprintf("%s%s", path, key)
				}
				fmt.Printf("%s\n", path)
			}
		}
		return nil
	})

	r.Dispatch("delete", &Help{
		Summary: "Remove one or more path from the Vault",
		Usage:   "safe delete [-rf] PATH [PATH ...]",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)

		if len(args) < 1 {
			r.ExitWithUsage("delete")
		}
		v := connect(true)
		for _, path := range args {
			_, key := vault.ParsePath(path)
			//Ignore -r if path has a key because that makes no sense
			if opt.Delete.Recurse && key == "" {
				if !opt.Delete.Force && !recursively("delete", path) {
					continue /* skip this command, process the next */
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
		rc.Apply(opt.UseTarget)
		if len(args) < 1 {
			args = append(args, "secret")
		}
		v := connect(true)
		data := make(map[string]*vault.Secret)
		for _, path := range args {
			tree, err := v.Tree(path, vault.TreeOptions{
				StripSlashes: true,
			})
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
		rc.Apply(opt.UseTarget)
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		var data map[string]*vault.Secret
		err = json.Unmarshal(b, &data)
		if err != nil {
			return err
		}

		if opt.SkipIfExists {
			fmt.Fprintf(os.Stderr, "@R{!!} @C{--no-clobber} @R{is incompatible with} @C{safe import}\n")
			r.ExitWithUsage("import")
		}

		v := connect(true)
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
		Usage:   "safe move [-rf] OLD-PATH NEW-PATH",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)
		if len(args) != 2 {
			r.ExitWithUsage("move")
		}

		v := connect(true)

		//Don't try to recurse if operating on a key
		// args[0] is the source path. args[1] is the destination path.
		if opt.Move.Recurse && !vault.PathHasKey(args[0]) && !vault.PathHasKey(args[1]) {
			if !opt.Move.Force && !recursively("move", args...) {
				return nil /* skip this command, process the next */
			}
			if err := v.MoveCopyTree(args[0], args[1], v.Move, opt.SkipIfExists, opt.Quiet); err != nil && !(vault.IsNotFound(err) && opt.Move.Force) {
				return err
			}
		} else {
			if err := v.Move(args[0], args[1], opt.SkipIfExists, opt.Quiet); err != nil && !(vault.IsNotFound(err) && opt.Move.Force) {
				return err
			}
		}
		return nil
	})

	r.Dispatch("copy", &Help{
		Summary: "Copy a secret from one path to another",
		Usage:   "safe copy [-Rf] OLD-PATH NEW-PATH",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)

		if len(args) != 2 {
			r.ExitWithUsage("copy")
		}
		v := connect(true)

		//Don't try to recurse if operating on a key
		// args[0] is the source path. args[1] is the destination path.
		if opt.Copy.Recurse && !vault.PathHasKey(args[0]) && !vault.PathHasKey(args[1]) {
			if !opt.Copy.Force && !recursively("copy", args...) {
				return nil /* skip this command, process the next */
			}
			if err := v.MoveCopyTree(args[0], args[1], v.Copy, opt.SkipIfExists, opt.Quiet); err != nil && !(vault.IsNotFound(err) && opt.Copy.Force) {
				return err
			}
		} else {
			if err := v.Copy(args[0], args[1], opt.SkipIfExists, opt.Quiet); err != nil && !(vault.IsNotFound(err) && opt.Copy.Force) {
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
		rc.Apply(opt.UseTarget)

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

		v := connect(true)

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
			exists := (err == nil)
			if opt.SkipIfExists && exists && s.Has(key) {
				if !opt.Quiet {
					fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to update} @C{%s:%s} @R{as it is already present in Vault}\n", path, key)
				}
				continue
			}
			err = s.Password(key, length, opt.Gen.Policy, opt.SkipIfExists)
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
		rc.Apply(opt.UseTarget)
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

		v := connect(true)
		for _, path := range args {
			s, err := v.Read(path)
			if err != nil && !vault.IsNotFound(err) {
				return err
			}
			exists := (err == nil)
			if opt.SkipIfExists && exists && (s.Has("private") || s.Has("public") || s.Has("fingerprint")) {
				if !opt.Quiet {
					fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to generate an SSH key at} @C{%s} @R{as it is already present in Vault}\n", path)
				}
				continue
			}
			if err = s.SSHKey(bits, opt.SkipIfExists); err != nil {
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
		rc.Apply(opt.UseTarget)
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

		v := connect(true)
		for _, path := range args {
			s, err := v.Read(path)
			if err != nil && !vault.IsNotFound(err) {
				return err
			}
			exists := (err == nil)
			if opt.SkipIfExists && exists && (s.Has("private") || s.Has("public")) {
				if !opt.Quiet {
					fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to generate an RSA key at} @C{%s} @R{as it is already present in Vault}\n", path)
				}
				continue
			}
			if err = s.RSAKey(bits, opt.SkipIfExists); err != nil {
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
		rc.Apply(opt.UseTarget)
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
		v := connect(true)
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		exists := (err == nil)
		if opt.SkipIfExists && exists && s.Has("dhparam-pem") {
			if !opt.Quiet {
				fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to generate a Diffie-Hellman key exchange parameter set at} @C{%s} @R{as it is already present in Vault}\n", path)
			}
			return nil
		}
		if err = s.DHParam(bits, opt.SkipIfExists); err != nil {
			return err
		}
		return v.Write(path, s)
	})

	r.Dispatch("prompt", &Help{
		Summary: "Print a prompt (useful for scripting safe command sets)",
		Usage:   "safe echo Your Message Here:",
		Type:    NonDestructiveCommand,
	}, func(command string, args ...string) error {
		// --no-clobber is ignored here, because there's no context of what you're
		// about to be writing after a prompt, so not sure if we should or shouldn't prompt
		// if you need to write something and prompt, but only if it isnt already present
		// in vault, see the `ask` subcommand
		fmt.Fprintf(os.Stderr, "%s\n", strings.Join(args, " "))
		return nil
	})

	r.Dispatch("vault", &Help{
		Summary: "Run arbitrary Vault CLI commands against the current target",
		Usage:   "safe vault ...",
		Type:    DestructiveCommand,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)

		if opt.SkipIfExists {
			fmt.Fprintf(os.Stderr, "@C{--no-clobber} @Y{specified, but is ignored for} @C{safe vault}\n")
		}

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

	r.Dispatch("rekey", &Help{
		Summary: "Re-key your Vault with new unseal keys",
		Usage:   "safe rekey [--gpg email@address ...] [--keys #] [--threshold #]",
		Type:    DestructiveCommand,
		Description: `
Rekeys Vault with new unseal keys. This will require a quorum
of existing unseal keys to accomplish. This command can be used
to change the nubmer of unseal keys being generated via --keys,
as well as the number of keys required to unseal the Vault via
--threshold.

If --gpg flags are provided, they will be used to look up in the
local GPG keyring public keys to give Vault for encrypting the new
unseal keys (one pubkey per unseal key). Output will have the
encrypted unseal keys, matched up with the email address associated
with the public key that it was encrypted with. Additionally, a
backup of the encrypted unseal keys is located at sys/rekey/backup
in Vault.

If no --gpg flags are provided, the output will include the raw
unseal keys, and should be treated accordingly.

`,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)

		unsealKeys := 5 // default to 5
		var gpgKeys []string
		if len(opt.Rekey.GPG) > 0 {
			unsealKeys = len(opt.Rekey.GPG)
			for _, email := range opt.Rekey.GPG {
				output, err := exec.Command("gpg", "--export", email).Output()
				if err != nil {
					return fmt.Errorf("Failed to retrieve GPG key for %s from local keyring: %s", email, err.Error())
				}

				// gpg --export returns 0, with no stdout if the key wasn't found, so handle that
				if output == nil || len(output) == 0 {
					return fmt.Errorf("No GPG key found for %s in the local keyring", email)
				}
				gpgKeys = append(gpgKeys, base64.StdEncoding.EncodeToString(output))
			}
		}

		// if specified, --unseal-keys takes priority, then the number of --gpg-keys, and a default of 5
		if opt.Rekey.NKeys != 0 {
			unsealKeys = opt.Rekey.NKeys
		}
		if len(opt.Rekey.GPG) > 0 && unsealKeys != len(opt.Rekey.GPG) {
			return fmt.Errorf("Both --gpg and --keys were specified, and their counts did not match.")
		}

		// if --threshold isn't specified, use a default (unless default is > the number of keys
		if opt.Rekey.Threshold == 0 {
			opt.Rekey.Threshold = 3
			if opt.Rekey.Threshold > unsealKeys {
				opt.Rekey.Threshold = unsealKeys
			}
		}
		if opt.Rekey.Threshold > unsealKeys {
			return fmt.Errorf("You specified only %d unseal keys, but are requiring %d keys to unseal vault. This is bad.", unsealKeys, opt.Rekey.Threshold)
		}
		if opt.Rekey.Threshold < 2 && unsealKeys > 1 {
			return fmt.Errorf("When specifying more than 1 unseal key, you must also have more than one key required to unseal.")
		}

		v := connect(true)
		keys, err := v.ReKey(unsealKeys, opt.Rekey.Threshold, gpgKeys)
		if err != nil {
			return err
		}
		fmt.Printf("@G{Your Vault has been re-keyed.} Please take note of your new unseal keys and @R{store them safely!}\n")
		for i, key := range keys {
			if len(opt.Rekey.GPG) == len(keys) {
				fmt.Printf("Unseal key for @c{%s}:\n@y{%s}\n", opt.Rekey.GPG[i], key)
			} else {
				fmt.Printf("Unseal key %d: @y{%s}\n", i+1, key)
			}
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
    bcrypt          Salt and hash the value, using bcrypt (Blowfish, in crypt format).
    crypt-md5       Salt and hash the value, using MD5, in crypt format (legacy).
    crypt-sha256    Salt and hash the value, using SHA-256, in crypt format.
    crypt-sha512    Salt and hash the value, using SHA-512, in crypt format.

`,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)

		if len(args) != 4 {
			r.ExitWithUsage("fmt")
		}

		fmtType := args[0]
		path := args[1]
		oldKey := args[2]
		newKey := args[3]

		v := connect(true)
		s, err := v.Read(path)
		if err != nil {
			return err
		}
		if opt.SkipIfExists && s.Has(newKey) {
			if !opt.Quiet {
				fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to reformat} @C{%s:%s} @R{to} @C{%s} @R{as it is already present in Vault}\n", path, oldKey, newKey)
			}
			return nil
		}
		if err = s.Format(oldKey, newKey, fmtType, opt.SkipIfExists); err != nil {
			if vault.IsNotFound(err) {
				return fmt.Errorf("%s:%s does not exist, cannot create %s encoded copy at %s:%s", path, oldKey, fmtType, path, newKey)
			}
			return fmt.Errorf("Error encoding %s:%s as %s: %s", path, oldKey, fmtType, err)
		}

		return v.Write(path, s)
	})

	r.Dispatch("curl", &Help{
		Summary: "Issue arbitrary HTTP requests to the current Vault (for diagnostics)",
		Usage:   "safe curl [OPTIONS] METHOD REL-URI [DATA]",
		Type:    DestructiveCommand,
		Description: `
This is a debugging and diagnostics tool.  You should not need to use
'safe curl' for normal operation or interaction with a Vault.

METHOD must be one of GET, LIST, POST, or PUT.

REL-URI is the relative URI (the path component, starting with the first
forward slash) of the resource you wish to access.

DATA should be a JSON string, since almost all of the Vault API handlers
deal exclusively in JSON payloads.  GET requests should not have DATA.
Query string parameters should be appended to REL-URI, instead of being
sent as DATA.
`,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)

		var (
			url, method string
			data        []byte
		)

		method = "GET"
		if len(args) < 1 {
			r.ExitWithUsage("curl")
		} else if len(args) == 1 {
			url = args[0]
		} else {
			method = strings.ToUpper(args[0])
			url = args[1]
			data = []byte(strings.Join(args[2:], " "))
		}

		v := connect(true)
		res, err := v.Curl(method, url, data)
		if err != nil {
			return err
		}

		if opt.Curl.DataOnly {
			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s\n", string(b))

		} else {
			r, _ := httputil.DumpResponse(res, true)
			fmt.Fprintf(os.Stdout, "%s\n", r)
		}
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
    IP addresses), Key Usage, Extended Key Usage, and TTL/expiry.


  @G{x509 revoke} [OPTIONS] path/to/cert

    Revokes an X.509 certificate that was issues by one of our CAs.


  @G{x509 crl} [OPTIONS] path/to/ca

    Manages a certificate revocation list, primarily to renew it
    (resigning it for freshness / liveness).


  @G{x509 validate} [OPTIONS] path/to/cert

    Validate a certificate in the Vault, checking to make sure that
    its private and public keys match, checking CA signatories,
    expiration, name applicability, etc.

  @G{x509 show} path/to/cert [path/to/other/cert ...]

    Print out a human-readable description of the certificate,
    including its subject name, issuer (CA), expiration and lifetime,
    and what domains, email addresses, and IP addresses it represents.

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

		rc.Apply(opt.UseTarget)
		v := connect(true)

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

			fmt.Printf("@G{%s} checks out.\n", path)
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

  -u, --key-usage   An x509 key usage or extended key usage. Can be specified
                    once for each desired usage. Valid key usage values are:
                    'digital_signature', 'non_repudiation', 'key_encipherment',
                    'data_encipherment', 'key_agreement', 'key_cert_sign',
                    'crl_sign', 'encipher_only', or 'decipher_only'. Valid
                    extended key usages are 'client_auth', 'server_auth', 'code_signing',
                    'email_protection', or 'timestamping'
	`,
	}, func(command string, args ...string) error {
		rc.Apply(opt.UseTarget)

		var ca *vault.X509

		if len(args) != 1 || len(opt.X509.Issue.Name) == 0 {
			r.ExitWithUsage("x509 issue")
		}

		if opt.X509.Issue.Subject == "" {
			opt.X509.Issue.Subject = fmt.Sprintf("CN=%s", opt.X509.Issue.Name[0])
		}

		v := connect(true)
		if opt.SkipIfExists {
			if _, err := v.Read(args[0]); err == nil {
				if !opt.Quiet {
					fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to create a new certificate in} @C{%s} @R{as it is already present in Vault}\n", args[0])
				}
				return nil
			} else if err != nil && !vault.IsNotFound(err) {
				return err
			}
		}

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

		cert, err := vault.NewCertificate(opt.X509.Issue.Subject,
			opt.X509.Issue.Name, opt.X509.Issue.KeyUsage, opt.X509.Issue.Bits)
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

			s, err := ca.Secret(opt.SkipIfExists)
			if err != nil {
				return err
			}
			err = v.Write(opt.X509.Issue.SignedBy, s)
			if err != nil {
				return err
			}
		}

		s, err := cert.Secret(opt.SkipIfExists)
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

		rc.Apply(opt.UseTarget)
		v := connect(true)

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
		s, err = ca.Secret(false) // SkipIfExists doesnt make sense in the context of revoke
		if err != nil {
			return err
		}

		err = v.Write(opt.X509.Revoke.SignedBy, s)
		if err != nil {
			return err
		}

		return nil
	})

	r.Dispatch("x509 show", &Help{
		Summary: "Show the details of an X.509 Certificate",
		Usage:   "safe x509 show path [path ...]",
		Description: `
When dealing with lots of different X.509 Certificates, it is important
to be able to identify what lives at each path in the vault.  This command
prints out information about a certificate, including:

  - Who issued it?
  - Is it a Certificate Authority?
  - What names / IPs is it valid for?
  - When does it expire?

`,
	}, func(command string, args ...string) error {
		if len(args) == 0 {
			r.ExitWithUsage("x509 show")
		}

		rc.Apply(opt.UseTarget)
		v := connect(true)

		for _, path := range args {
			s, err := v.Read(args[0])
			if err != nil {
				return err
			}

			fmt.Printf("%s:\n", path)
			cert, err := s.X509()
			if err != nil {
				fmt.Printf("  !! %s\n\n", err)
				continue
			}

			fmt.Printf("  @G{%s}\n", cert.Subject())
			if cert.Subject() != cert.Issuer() {
				fmt.Printf("  issued by: @C{%s}\n", cert.Issuer())
			}

			fmt.Printf("\n")
			toStart := cert.Certificate.NotBefore.Sub(time.Now())
			toEnd := cert.Certificate.NotAfter.Sub(time.Now())

			days := int(toStart.Hours() / 24)
			if days == 1 {
				fmt.Printf("  @Y{not valid for another day}\n")
			} else if days > 1 {
				fmt.Printf("  @Y{not valid for another %d days}\n", days)
			}

			days = int(toEnd.Hours() / 24)
			if days < -1 {
				fmt.Printf("  @R{EXPIRED %d days ago}\n", -1*days)
			} else if days < 0 {
				fmt.Printf("  @R{EXPIRED a day ago}\n")
			} else if days < 1 {
				fmt.Printf("  @R{EXPIRED}\n")
			} else if days == 1 {
				fmt.Printf("  @Y{expires in a day}\n")
			} else if days < 30 {
				fmt.Printf("  @Y{expires in %d days}\n", days)
			} else {
				fmt.Printf("  expires in @G{%d days}\n", days)
			}
			fmt.Printf("  valid from @C{%s} - @C{%s}", cert.Certificate.NotBefore.Format("Jan 2 2006"), cert.Certificate.NotAfter.Format("Jan 2 2006"))

			life := int(cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore).Hours())
			if life < 360*24 {
				fmt.Printf(" (@M{~%d days})\n", life/24)
			} else {
				fmt.Printf(" (@M{~%d years})\n", life/365/24)
			}

			fmt.Printf("  for the following names:\n")
			for _, s := range cert.Certificate.DNSNames {
				fmt.Printf("    - @G{%s} (DNS)\n", s)
			}
			for _, s := range cert.Certificate.EmailAddresses {
				fmt.Printf("    - @G{%s} (email)\n", s)
			}
			for _, s := range cert.Certificate.IPAddresses {
				fmt.Printf("    - @G{%s} (IP)\n", s)
			}
			fmt.Printf("\n")
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

		rc.Apply(opt.UseTarget)
		v := connect(true)

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
		s, err = ca.Secret(false) // SkipIfExists doesn't make sense in the context of crl regeneration
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
		fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
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
		opt.SkipIfExists = !opt.Clobber

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
				fmt.Fprintf(os.Stderr, "@Y{%s}\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
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
		fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}
}

func recursively(cmd string, args ...string) bool {
	y := prompt.Normal("Recursively @R{%s} @C{%s} @Y{(y/n)} ", cmd, strings.Join(args, " "))
	y = strings.TrimSpace(y)
	return y == "y" || y == "yes"
}
