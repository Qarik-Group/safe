package main

import (
	"io"

	fmt "github.com/jhunt/go-ansi"
)

// envPrintFunc abstracts the printing of environment variables for various
// shells.
type envPrintFunc func(io.Writer, map[string]string) error

func printEnv(out io.Writer, vars map[string]string) error {
	for name, value := range vars {
		if value != "" {
			fmt.Fprintf(out, "  @B{%s}  @G{%s}\n", name, value)
		}
	}
	return nil
}

// printEnvForBash prints the given map to the writer so that it can be used
// directly within an `eval` call in Bash or ZSH.
func printEnvForBash(out io.Writer, vars map[string]string) error {
	for name, value := range vars {
		if value != "" {
			fmt.Fprintf(out, "\\export %s=%s;\n", name, value)
		} else {
			fmt.Fprintf(out, "\\unset %s;\n", name)
		}
	}
	return nil
}

// printEnvForFish prints the given map to the writer so that it can be used
// directly within an `eval` call in Fish.
func printEnvForFish(out io.Writer, vars map[string]string) error {
	for name, value := range vars {
		if value == "" {
			fmt.Fprintf(out, "set -u %s %s;\n", name, value)
		} else {
			fmt.Fprintf(out, "set -x %s %s;\n", name, value)
		}
	}
	return nil
}
