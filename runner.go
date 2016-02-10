package main

import (
	"fmt"
)

type Handler func (command string, args ...string) error

type Runner struct {
	Handlers map[string] Handler
	Aliases  map[string] string
}

func NewRunner() *Runner {
	return &Runner{
		Handlers: make(map[string] Handler),
		Aliases:  make(map[string] string),
	}
}

func (r *Runner) Dispatch(command string, fn Handler, aliases ...string) {
	r.Handlers[command] = fn
	for _, alias := range aliases {
		r.Aliases[alias] = command
	}
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
