package prompt

import (
	"bufio"
	"os"
	"strings"

	"github.com/jhunt/ansi"
	"github.com/mattn/go-isatty"
	"golang.org/x/crypto/ssh/terminal"
)

func Normal(label string, args ...interface{}) string {
	ansi.Printf(label, args...)
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSuffix(s, "\n")
}

func Secure(label string, args ...interface{}) string {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimSuffix(s, "\n")
	}

	ansi.Printf(label, args...)
	b, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	ansi.Printf("\n")
	return string(b)
}
