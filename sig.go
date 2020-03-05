package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func Signals() {
	prev, err := terminal.GetState(int(os.Stdin.Fd()))
	if err != nil {
		prev = nil
	}

	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	for range s {
		terminal.Restore(int(os.Stdin.Fd()), prev)
		os.Exit(1)
	}
}
