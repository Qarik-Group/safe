package main

import (
	"fmt"
	"io/ioutil"
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

func keyPrompt(key string, confirm bool) (string, string, error) {
	if strings.Index(key, "=") >= 0 {
		l := strings.SplitN(key, "=", 2)
		if l[1] == "" {
			l[1] = pr(l[0], confirm)
		}
		ansi.Printf("%s: @G{%s}\n", l[0], l[1])
		return l[0], l[1], nil

	} else if strings.Index(key, "@") >= 0 {
		l := strings.SplitN(key, "@", 2)
		if l[1] == "" {
			return l[0], pr(l[0], confirm), nil
		}
		b, err := ioutil.ReadFile(l[1])
		if err != nil {
			return l[0], "", fmt.Errorf("Failed to read contents of %s: %s", l[1], err)
		}
		ansi.Printf("%s: <@C{%s}\n", l[0], l[1])
		return l[0], string(b), nil
	}
	return key, pr(key, confirm), nil
}

func pr(label string, confirm bool) string {
	if !confirm {
		return prompt.Secure("%s: ", label)
	}

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
