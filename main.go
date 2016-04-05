package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/jhunt/safe/vault"
)

var Version string

func connect() *vault.Vault {
	v, err := vault.NewVault(os.Getenv("VAULT_ADDR"), "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	return v
}

func main() {
	go Signals()

	r := NewRunner()
	r.Dispatch("version", func(command string, args ...string) error {
		if Version != "" {
			fmt.Printf("safe v%s\n", Version)
		} else {
			fmt.Printf("safe (development build)\n")
		}
		os.Exit(0)
		return nil
	}, "-v", "--version")

	r.Dispatch("help", func(command string, args ...string) error {
		fmt.Fprintf(os.Stderr, `Usage: safe <cmd> <args ...>

    Valid subcommands are:

    get path [path ...]
           Retrieve and print the values of one or more paths.

    set path key[=value] [key ...]
           Update a single path with new keys.  Any existing keys that are
           not specified on the command line are left intact.You will be
           prompted to enter values for any keys that do not have values.
           This can be used for more sensitive credentials like passwords,
           PINs, etc.

    paths path [path ... ]
           Provide a flat listing of all reachable keys for each path.

    tree path [path ...]
           Provide a tree hierarchy listing of all reachable keys for each path.

    delete path [path ...]
           Remove multiple paths from the Vault.

    move oldpath newpath
           Move a secret from oldpath to newpath, a rename of sorts.

    copy oldpath newpath
           Copy a secret from oldpath to newpath.

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

    prompt ...
           Echo the arguments, space-separated, as a single line to the terminal.

    import <export.file
           Read from STDIN an export file and write all of the secrets contained
           therein to the same paths inside the Vault

    export path [path ...]
           Export the given subtree(s) in a format suitable for migration (via a
           future import call), or long-term storage offline.
`)
		os.Exit(0)
		return nil
	}, "-h", "--help")

	r.Dispatch("set", func(command string, args ...string) error {
		if len(args) < 2 {
			return fmt.Errorf("USAGE: set path key[=value] [key ...]")
		}
		v := connect()
		path, args := args[0], args[1:]
		s, err := v.Read(path)
		if err != nil && err != vault.NotFound {
			return err
		}
		for _, set := range args {
			k, v := keyPrompt(set)
			s.Set(k, v)
		}
		return v.Write(path, s)
	}, "write")

	r.Dispatch("get", func(command string, args ...string) error {
		if len(args) < 1 {
			return fmt.Errorf("USAGE: get path [path ...]")
		}
		v := connect()
		for _, path := range args {
			s, err := v.Read(path)
			if err != nil {
				return err
			}
			fmt.Printf("--- # %s\n", path)
			fmt.Printf("%s\n\n", s.YAML())
		}
		return nil
	}, "read", "cat")

	r.Dispatch("tree", func(command string, args ...string) error {
		if len(args) == 0 {
			args = append(args, "secret")
		}
		v := connect()
		for _, path := range args {
			tree, err := v.Tree(path, true)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", tree.Draw())
		}
		return nil
	})

	r.Dispatch("paths", func(command string, args ...string) error {
		if len(args) < 1 {
			return fmt.Errorf("USAGE: paths path [path ...]")
		}
		v := connect()
		for _, path := range args {
			tree, err := v.Tree(path, false)
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
		if len(args) < 1 {
			return fmt.Errorf("USAGE: delete path [path ...]")
		}
		v := connect()
		for _, path := range args {
			if err := v.Delete(path); err != nil {
				return err
			}
		}
		return nil
	}, "rm")

	r.Dispatch("export", func(command string, args ...string) error {
		if len(args) < 1 {
			return fmt.Errorf("USAGE: export path [path ...]")
		}
		v := connect()
		data := make(map[string]*vault.Secret)
		for _, path := range args {
			tree, err := v.Tree(path, false)
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
			fmt.Printf("wrote %s\n", path)
		}
		return nil
	})

	r.Dispatch("move", func(command string, args ...string) error {
		if len(args) != 2 {
			return fmt.Errorf("USAGE: move oldpath newpath")
		}
		v := connect()
		return v.Move(args[0], args[1])
	}, "mv", "rename")

	r.Dispatch("copy", func(command string, args ...string) error {
		if len(args) != 2 {
			return fmt.Errorf("USAGE: copy oldpath newpath")
		}
		v := connect()
		return v.Copy(args[0], args[1])
	}, "cp")

	r.Dispatch("gen", func(command string, args ...string) error {
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
		if err != nil && err != vault.NotFound {
			return err
		}
		s.Password(key, length)
		if err = v.Write(path, s); err != nil {
			return err
		}
		return nil
	}, "auto")

	r.Dispatch("ssh", func(command string, args ...string) error {
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
			if err != nil && err != vault.NotFound {
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
			if err != nil && err != vault.NotFound {
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

	r.Dispatch("prompt", func(command string, args ...string) error {
		fmt.Printf("%s\n", strings.Join(args, " "))
		return nil
	})

	if len(os.Args) < 2 {
		os.Args = append(os.Args, "help")
	}

	if err := r.Run(os.Args[1:]...); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
