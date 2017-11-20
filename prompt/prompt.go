package prompt

import (
	"bufio"
	"os"
	"strings"

	"github.com/jhunt/go-ansi"
	"github.com/mattn/go-isatty"
	"golang.org/x/crypto/ssh/terminal"
)

func Normal(label string, args ...interface{}) string {
	ansi.Fprintf(os.Stderr, label, args...)
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSuffix(s, "\n")
}

func Secure(label string, args ...interface{}) string {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimSuffix(s, "\n")
	}

	ansi.Fprintf(os.Stderr, label, args...)
	b, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	ansi.Fprintf(os.Stderr, "\n")
	return string(b)
}
