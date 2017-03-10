package cli

import (
	"os"
)

/* Parse looks through os.Args, and returns the sub-command name
   (or "" for none), the remaining positional arguments, and any
   error that was encountered. */
func Parse(thing interface{}) (string, []string, error) {
	return ParseArgs(thing, os.Args[1:])
}

/* ParseArgs is like Parse(), except that it operates on an explicit
   list of arguments, instead of implicitly using os.Args. */
func ParseArgs(thing interface{}, args []string) (string, []string, error) {
	p, err := NewParser(thing, args)
	if err != nil {
		return "", nil, err
	}

	if len(p.rest) == 0 {
		return p.Command, p.Args, p.Error()
	}

	if p.rest[0] == "--" {
		return p.Command, append(p.Args, p.rest[1:]...), p.Error()
	}

	p.Next()
	return p.Command, append(p.Args, p.rest...), p.Error()
}
