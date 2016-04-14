package prompt

import (
	"os"
	"bufio"

	"golang.org/x/crypto/ssh/terminal"
	"github.com/jhunt/ansi"
)

func Normal(label string, args ...interface{}) string {
	ansi.Printf(label, args...)
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return s
}

func Secure(label string, args ...interface{}) string {
	ansi.Printf(label, args...)
	b, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	ansi.Printf("\n")
	return string(b)
}
