package main

import (
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
	"github.com/jhunt/ansi"
)

func fail(err error) {
	if err != nil {
		ansi.Fprintf(os.Stderr, "failed: @R{%s}\n", err)
		os.Exit(2)
	}
}

func keyPrompt(key string) (string, string) {
	if strings.Index(key, "=") >= 0 {
		l := strings.SplitN(key, "=", 2)
		if l[1] == "" {
			l[1] = prompt(l[0])
		}
		return l[0], l[1]
	}
	return key, prompt(key)
}

func prompt(label string) string {
	for {
		ansi.Printf("%s @Y{[hidden]:} ", label)
		a_, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		ansi.Printf("\n")
		fail(err)

		ansi.Printf("%s @C{[confirm]:} ", label)
		b_, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		ansi.Printf("\n")
		fail(err)

		a, b := string(a_), string(b_)
		if a == b && a != "" {
			ansi.Printf("\n")
			return a
		}
		ansi.Printf("\n@Y{oops, try again }(Ctrl-C to cancel)\n\n")
	}
}
