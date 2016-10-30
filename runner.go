package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/starkandwayne/goutils/ansi"
)

const (
	DestructiveCommand    string = "@R"
	NonDestructiveCommand        = "@G"
	AdministrativeCommand        = "@W"
	MiscellaneousCommand         = "@W"
)

type Help struct {
	Summary     string
	Usage       string
	Description string
	Type        string
}

type Handler func(command string, args ...string) error

type Runner struct {
	Handlers map[string]Handler
	Aliases  map[string]string
	Topics   map[string]*Help
}

func NewRunner() *Runner {
	return &Runner{
		Handlers: make(map[string]Handler),
		Aliases:  make(map[string]string),
		Topics:   make(map[string]*Help),
	}
}

func (r *Runner) Dispatch(command string, help *Help, fn Handler, aliases ...string) {
	if help != nil {
		help.Description = strings.Trim(help.Description, "\n")
	}

	r.Handlers[command] = fn
	r.Topics[command] = help
	for _, alias := range aliases {
		r.Aliases[alias] = command
	}
}

func (r *Runner) HelpTopic(topic string, help string) {
	r.Topics[topic] = &Help{Description: strings.Trim(help, "\n")}
}

func (r *Runner) Help(out io.Writer, topic string) {
	if topic == "commands" {
		fmt.Fprintf(out, "Valid commands are:\n\n")

		ll := make([]string, 0)
		for cmd := range r.Handlers {
			ll = append(ll, cmd)
		}

		sort.Strings(ll)
		for _, cmd := range ll {
			if h := r.Topics[cmd]; h != nil {
				f := h.Type
				if f == "" {
					f = "@W"
				}
				ansi.Fprintf(out, "    "+f+"{%-10s}  %s\n", cmd, h.Summary)
			}
		}

		fmt.Fprintf(out, "\nTry 'safe help <command>' for detailed information\n")
		return
	}

	if help, ok := r.Topics[topic]; ok && help != nil {
		if help.Summary != "" {
			/* this is a command, print it like one */
			ansi.Fprintf(out, "safe @G{%s} - @C{%s}\n", topic, help.Summary)
			if help.Usage != "" {
				ansi.Fprintf(out, "USAGE: "+help.Usage+"\n")
			}
			if help.Description != "" {
				ansi.Fprintf(out, "\n")
			}
		}
		if help.Description != "" {
			ansi.Fprintf(out, help.Description+"\n")
		}
		return
	}

	ansi.Fprintf(out, "@R{Unrecognized command or help topic '%s'}\n", topic)
	fmt.Fprintf(out, "Try 'safe help' to get started with safe,\n")
	fmt.Fprintf(out, " or 'safe commands' for a list of valid commands\n")
	os.Exit(1)
}

func (r *Runner) ExitWithUsage(topic string) {
	if help, ok := r.Topics[topic]; ok && help != nil {
		if help.Summary != "" {
			/* this is a command, print it like one */
			ansi.Fprintf(os.Stderr, "safe @G{%s} - @C{%s}\n", topic, help.Summary)
			if help.Usage != "" {
				ansi.Fprintf(os.Stderr, "USAGE: "+help.Usage+"\n")
			}
		}
	}
	os.Exit(1)
}

func (r *Runner) Execute(args ...string) error {
	if len(args) < 1 {
		return nil
	}
	command, args := args[0], args[1:]
	if fn, ok := r.Handlers[command]; ok {
		return fn(command, args...)
	}

	if alias, ok := r.Aliases[command]; ok {
		if fn, ok := r.Handlers[alias]; ok {
			return fn(command, args...)
		}
	}

	return fmt.Errorf("unknown command '%s'", command)
}

func (r *Runner) Run(args ...string) error {
	l := make([]string, 0)
	for _, arg := range args {
		if arg == "--" {
			if err := r.Execute(l...); err != nil {
				return err
			}
			l = make([]string, 0)
			continue
		}
		l = append(l, arg)
	}
	return r.Execute(l...)
}
