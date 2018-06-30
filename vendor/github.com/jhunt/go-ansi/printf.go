package ansi

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"unicode"

	"github.com/mattn/go-isatty"
)

var (
	colors = map[string]string{
		"k": "00;30", // black
		"K": "01;30", // black (BOLD)

		"r": "00;31", // red
		"R": "01;31", // red (BOLD)

		"g": "00;32", // green
		"G": "01;32", // green (BOLD)

		"y": "00;33", // yellow
		"Y": "01;33", // yellow (BOLD)

		"b": "00;34", // blue
		"B": "01;34", // blue (BOLD)

		"m": "00;35", // magenta
		"M": "01;35", // magenta (BOLD)
		"p": "00;35", // magenta
		"P": "01;35", // magenta (BOLD)

		"c": "00;36", // cyan
		"C": "01;36", // cyan (BOLD)

		"w": "00;37", // white
		"W": "01;37", // white (BOLD)
	}

	re = regexp.MustCompile(`(?s)@[kKrRgGyYbBmMpPcCwW*]{.*?}`)
	st = regexp.MustCompile("\033\\[\\d+(;\\d+)?m")
)

var (
	force bool
)

func ForceColor(c bool) {
	force = c
}

func strip(s string) string {
	return st.ReplaceAllString(s, "")
}

func colorize(s string) string {
	return re.ReplaceAllStringFunc(s, func(m string) string {
		if m[1:2] == "*" {
			rainbow := "RYGCBM"
			s := ""
			i := 0
			for _, c := range m[3 : len(m)-1] {
				if unicode.IsSpace(c) {
					s += string(c)
					continue
				}

				j := i % len(rainbow)
				s += "\033[" + colors[rainbow[j:j+1]] + "m" + string(c) + "\033[00m"
				i++
			}
			return s
		}
		return "\033[" + colors[m[1:2]] + "m" + m[3:len(m)-1] + "\033[00m"
	})
}

func CanColorize(out io.Writer) bool {
	f, ok := out.(*os.File)
	if runtime.GOOS == "windows" {
		ok = false
	}
	return ok && isatty.IsTerminal(f.Fd())
}

func ShouldColorize(out io.Writer) bool {
	return force || CanColorize(out)
}

func Printf(format string, a ...interface{}) (int, error) {
	s := colorize(format)
	if !ShouldColorize(os.Stdout) {
		s = strip(s)
	}
	return fmt.Printf(s, a...)
}

func Fprintf(out io.Writer, format string, a ...interface{}) (int, error) {
	s := colorize(format)
	if !ShouldColorize(out) {
		s = strip(s)
	}
	return fmt.Fprintf(out, s, a...)
}

func Sprintf(format string, a ...interface{}) string {
	return fmt.Sprintf(colorize(format), a...)
}

func Errorf(format string, a ...interface{}) error {
	return fmt.Errorf(colorize(format), a...)
}
