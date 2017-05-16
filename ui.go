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

func parseKeyVal(key string) (string, string, error) {
	if strings.Index(key, "=") >= 0 {
		l := strings.SplitN(key, "=", 2)
		if l[1] == "" {
			return l[0], "", nil
		}
		ansi.Fprintf(os.Stderr, "%s: @G{%s}\n", l[0], l[1])
		return l[0], l[1], nil
	} else if strings.Index(key, "@") >= 0 {
		l := strings.SplitN(key, "@", 2)
		if l[1] == "" {
			return l[0], "", nil
		}
		b, err := ioutil.ReadFile(l[1])
		if err != nil {
			return l[0], "", fmt.Errorf("Failed to read contents of %s: %s", l[1], err)
		}
		ansi.Fprintf(os.Stderr, "%s: <@C{%s}\n", l[0], l[1])
		return l[0], string(b), nil
	}
	return key, "", nil
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
