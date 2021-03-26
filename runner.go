package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/jhunt/go-ansi"
)

const (
	DestructiveCommand    string = "@R"
	NonDestructiveCommand        = "@G"
	AdministrativeCommand        = "@W"
	MiscellaneousCommand         = "@W"
	HiddenCommand                = "HIDEME"
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
	Topics   map[string]*Help
}

func NewRunner() *Runner {
	return &Runner{
		Handlers: make(map[string]Handler),
		Topics:   make(map[string]*Help),
	}
}

func (r *Runner) Dispatch(command string, help *Help, fn Handler) {
	if help != nil {
		help.Description = strings.Trim(help.Description, "\n")
	}

	r.Handlers[command] = fn
	if help != nil && help.Type != HiddenCommand {
		r.Topics[command] = help
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

		fmt.Fprintf(out, "\nTry `safe envvars' for information on available environment variables\n")
		fmt.Fprintf(out, "Try 'safe help <command>' for detailed information on specific commands\n")
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

func (r *Runner) Execute(command string, args ...string) error {
	if fn, ok := r.Handlers[command]; ok {
		return fn(command, args...)
	}
	return fmt.Errorf("unknown command '%s'", command)
}
