package main

import (
	"fmt"
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

	r.Dispatch("move", func (command string, args ...string) error {
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
		fmt.Printf("%s\n", strings.Join(args, " "));
		return nil
	})

	if err := r.Run(os.Args[1:]...); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
