package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/starkandwayne/goutils/ansi"
	"github.com/starkandwayne/safe/prompt"
)

func warn(warning string, args ...interface{}) {
	ansi.Fprintf(os.Stderr, "warning: @Y{%s}\n", fmt.Sprintf(warning, args...))
}

func fail(err error) {
	if err != nil {
		ansi.Fprintf(os.Stderr, "failed: @R{%s}\n", err)
		os.Exit(2)
	}
}

func parseKeyVal(key string, quiet bool) (string, string, bool, error) {
	if strings.Index(key, "=") >= 0 {
		l := strings.SplitN(key, "=", 2)
		if l[1] == "" {
			return l[0], "", false, nil
		}
		if !quiet {
			ansi.Fprintf(os.Stderr, "%s: @G{%s}\n", l[0], l[1])
		}
		return l[0], l[1], false, nil
	} else if strings.Index(key, "@") >= 0 {
		l := strings.SplitN(key, "@", 2)
		if l[1] == "" {
			return l[0], "", true, fmt.Errorf("No file specified: expecting %s@<filename>", l[0])
		}

		if l[1] == "-" {
			b, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				return l[0], "", true, fmt.Errorf("Failed to read from standard input: %s", err)
			}
			if !quiet {
				ansi.Fprintf(os.Stderr, "%s: <@M{$stdin}\n", l[0])
			}
			return l[0], string(b), false, nil

		} else {
			b, err := ioutil.ReadFile(l[1])
			if err != nil {
				return l[0], "", true, fmt.Errorf("Failed to read contents of %s: %s", l[1], err)
			}
			if !quiet {
				ansi.Fprintf(os.Stderr, "%s: <@C{%s}\n", l[0], l[1])
			}
			return l[0], string(b), false, nil
		}
	}
	return key, "", true, nil
}

func pr(label string, confirm bool, secure bool) string {
	if !confirm {
		if secure {
			return prompt.Secure("%s: ", label)
		} else {
			return prompt.Normal("%s: ", label)
		}
	}

	for {
		a := prompt.Secure("%s @Y{[hidden]:} ", label)
		b := prompt.Secure("%s @C{[confirm]:} ", label)

		if a == b && a != "" {
			ansi.Fprintf(os.Stderr, "\n")
			return a
		}
		ansi.Fprintf(os.Stderr, "\n@Y{oops, try again }(Ctrl-C to cancel)\n\n")
	}
}
