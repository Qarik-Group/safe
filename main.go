package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/jhunt/safe/vault"
)

var Version string

func ok(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func notok(err error) {
	if err == nil {
		fmt.Fprintf(os.Stderr, "expected an error, but nothing failed!\n")
		os.Exit(1)
	}
}

func DELETE(v *vault.Vault, path string) {
	fmt.Printf("DELETE %s\n", path)
	err := v.Delete(path)
	ok(err)
	READ(v, path)
	fmt.Printf("\n")
}

func READ(v *vault.Vault, path string) {
	secret, _ := v.Read(path)
	fmt.Printf("READ %s: %v\n", path, secret)
}

func COPY(v *vault.Vault, oldpath, newpath string) {
	fmt.Printf("COPY %s -> %s\n", oldpath, newpath)
	err := v.Copy(oldpath, newpath)
	ok(err)
	READ(v, oldpath)
	READ(v, newpath)
	fmt.Printf("\n")
}

func MOVE(v *vault.Vault, oldpath, newpath string) {
	fmt.Printf("MOVE %s -> %s\n", oldpath, newpath)
	err := v.Move(oldpath, newpath)
	ok(err)
	READ(v, oldpath)
	READ(v, newpath)
	fmt.Printf("\n")
}

func main() {
	v, err := vault.NewVault(os.Getenv("VAULT_ADDR"), "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

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
		return v.Move(args[0], args[1])
	}, "mv", "rename")

	r.Dispatch("copy", func(command string, args ...string) error {
		if len(args) != 2 {
			return fmt.Errorf("USAGE: copy oldpath newpath")
		}
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

	err = r.Run(os.Args[1:]...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func main2() {
	fmt.Printf("starting up\n")
	v, err := vault.NewVault(os.Getenv("VAULT_ADDR"), "")
	ok(err)

	DELETE(v, "secret/other")
	DELETE(v, "secret/copy")
	READ(v, "secret/handshake")

	COPY(v, "secret/handshake", "secret/copy")
	MOVE(v, "secret/copy", "secret/other")

	DELETE(v, "secret/ssh")
	s := vault.NewSecret()
	err = s.SSHKey(2048); ok(err)
	err = v.Write("secret/ssh", s); ok(err)
	READ(v, "secret/ssh")

	DELETE(v, "secret/rsa")
	s = vault.NewSecret()
	err = s.RSAKey(2048); ok(err)
	err = v.Write("secret/rsa", s); ok(err)
	READ(v, "secret/rsa")

	fmt.Printf("shutting down...\n")
}
