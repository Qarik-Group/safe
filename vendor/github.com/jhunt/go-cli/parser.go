package cli

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/jhunt/go-snapshot"
)

type Parser struct {
	Command string
	Args    []string

	c    context
	err  error
	rest []string
	snap snapshot.Snapshot
}

func NewParser(thing interface{}, args []string) (*Parser, error) {
	c, err := reflectOnIt(thing)
	if err != nil {
		return nil, err
	}

	/* make sure we didn't do anything semantically invalid... */
	if err := validate(c); err != nil {
		return nil, err
	}

	/* keep track of the salient details */
	p := Parser{
		c:       c,
		Command: "",
		Args:    []string{},
	}

	/* parse the globals, but stop at the first non-option */
	if p.rest, err = parse(&c, nil, args); err != nil {
		return nil, err
	}

	/* snapshot so that we can revert to the globally-specified globals */
	if p.snap, err = snapshot.Take(thing); err != nil {
		return nil, err
	}

	return &p, nil
}

func (p *Parser) Error() error {
	return p.err
}

func (p *Parser) Next() bool {
	if len(p.rest) == 0 {
		return false
	}

	/* skip the chain separator */
	if p.rest[0] == "--" {
		p.rest = p.rest[1:]
	}

	/* revert the global state */
	err := p.snap.Revert()
	if err != nil {
		p.err = err
		return false
	}

	rest := p.rest     // contains the rest of the unparsed options
	args := []string{} // positional arguments
	cmd := []string{}  // sub-command stack
	lvl := p.c         // where we are in the sub-command depth
	for {
		if rest, err = parse(&p.c, cmd, rest); err != nil {
			p.err = err
			return false
		}

		if len(rest) == 0 {
			/* out of options */
			break
		}

		if rest[0] == "--" {
			rest = rest[1:]
			break
		}

		if len(args) != 0 {
			args = append(args, rest[0])

		} else if sub, ok := lvl.Subs[rest[0]]; ok {
			lvl = sub
			cmd = append(cmd, lvl.Command)

		} else {
			args = append(args, rest[0])
		}

		rest = rest[1:]
	}

	p.Command = strings.Join(cmd, " ")
	p.Args = args
	p.rest = rest
	return true
}

func parse(c *context, cmd, args []string) ([]string, error) {
	for len(args) > 0 {
		arg := args[0]
		if len(arg) == 0 || arg == "-" || arg == "--" || arg[0] != '-' {
			return args, nil
		}

		args = args[1:]
		if arg[1] == '-' { /* long option! */
			name := arg[2:]
			opt, err := c.findLong(cmd, name)
			if err != nil {
				return args, err
			}

			/* now we need to determine if we have a value arg or not.
			   `cli` uses a simple heuristic that works well in practice:

			     - bool receivers do not take value args
			     - everything else takes a value arg
			*/
			if opt.Kind == reflect.Bool {
				opt.enable(!strings.HasPrefix(name, "no-"))

			} else {
				if len(args) == 0 {
					return args, fmt.Errorf("missing required value for `%s` flag", arg)
				}
				if err = opt.set(args[0]); err != nil {
					return args, err
				}
				args = args[1:]
			}

		} else { /* short option(s)! */
			arg = arg[1:]
			for len(arg) > 0 {
				name := arg[0:1]
				arg = arg[1:]

				opt, err := c.findShort(cmd, name)
				if err != nil {
					return args, err
				}
				if opt.Kind == reflect.Bool {
					opt.enable(true)

				} else {
					/* attempt to use the rest of the short block, if there is one,
					   as the value arg... */
					if len(arg) > 0 {
						if err = opt.set(arg); err != nil {
							return args, err
						}
						break
					}
					/* otherwise, we need the next argument in the arg list... */
					if len(args) == 0 {
						return args, fmt.Errorf("missing required value for `-%s` flag", name)
					}
					if err = opt.set(args[0]); err != nil {
						return args, err
					}
					args = args[1:]
					break
				}
			}
		}
	}

	return args, nil
}
