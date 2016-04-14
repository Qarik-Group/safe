package main

import (
	"os"
	"strings"

	"github.com/jhunt/ansi"
	"github.com/jhunt/safe/prompt"
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
			l[1] = pr(l[0])
		}
		ansi.Printf("%s: @G{%s}\n", l[0], l[1])
		return l[0], l[1]
	}
	return key, pr(key)
}

func pr(label string) string {
	for {
		a := prompt.Secure("%s @Y{[hidden]:} ", label)
		b := prompt.Secure("%s @C{[confirm]:} ", label)

		if a == b && a != "" {
			ansi.Printf("\n")
			return a
		}
		ansi.Printf("\n@Y{oops, try again }(Ctrl-C to cancel)\n\n")
	}
}
