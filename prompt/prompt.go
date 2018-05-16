package prompt

import (
	"bufio"
	"os"
	"strings"

	"github.com/jhunt/go-ansi"
	"github.com/mattn/go-isatty"
	"golang.org/x/crypto/ssh/terminal"
)

var in *bufio.Reader

func readline() string {
	if in == nil {
		in = bufio.NewReader(os.Stdin)
	}

	s, _ := in.ReadString('\n')
	return strings.TrimSuffix(s, "\n")
}

func Normal(label string, args ...interface{}) string {
	ansi.Fprintf(os.Stderr, label, args...)
	return readline()
}

func Secure(label string, args ...interface{}) string {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return readline()
	}

	ansi.Fprintf(os.Stderr, label, args...)
	b, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	ansi.Fprintf(os.Stderr, "\n")
	return string(b)
}
