package main

import (
	"fmt"
	// not crypto, not significant
	"math/rand"
	"time"
)

var Adjectives []string
var Nouns []string

func init() {
	Adjectives = []string{
		"hardened",
		"toughened",
		"annealed",
		"tempered",
		"fortified",
		"bastioned",
		"bolstered",
		"reinforced",
		"inviolable",
		"impregnable",
		"unassailable",
		"impervious",
		"unbreakable",
		"infrangible",
		"stalwart",
		"sturdy",
		"stouthearted",
	}

	Nouns = []string{
		"garrison",
		"fortress",
		"castle",
		"keep",
		"outpost",
		"coffer",
		"zone",
		"sanctuary",
		"refuge",
		"asylum",
		"hold",
		"oubliette",
		"donjon",
		"dungeon",
		"gaol",
	}
}

func init() {
	rand.Seed(time.Now().Unix())
}

func RandomName() string {
	return fmt.Sprintf("%s-%s",
		Adjectives[rand.Intn(len(Adjectives))],
		Nouns[rand.Intn(len(Nouns))])
}
