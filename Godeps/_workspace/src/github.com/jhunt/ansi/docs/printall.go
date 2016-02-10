package main

import "github.com/jhunt/ansi"

func main() {
	ansi.Printf("\n\n\n  @R{A}@G{N}@Y{S}@B{I} Color Codes\n\n\n")
	var colors = []struct {
		Regular string
		Bold string
		Name string
	}{
		{"k", "K", "Black"},
		{"r", "R", "Red"},
		{"g", "G", "Green"},
		{"y", "Y", "Yellow"},
		{"b", "B", "Blue"},
		{"m", "M", "Magenta"},
		{"c", "C", "Cyan"},
		{"w", "W", "White"},
	}
	for _, c := range colors {
		ansi.Printf("  @%s is @"+c.Regular+"{%-10s}    @%s is @"+c.Bold+"{%s (bold)}\n", c.Regular, c.Name, c.Bold, c.Name)
	}
	ansi.Printf("\n\n\n")
}
