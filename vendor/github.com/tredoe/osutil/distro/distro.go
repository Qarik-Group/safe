// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package distro detects the Linux distribution.
package distro

import (
	"os"

	"github.com/tredoe/osutil/config/shconf"
)

// Distro represents a distribution of Linux system.
type Distro int

// Most used Linux distributions.
const (
	Arch Distro = iota + 1
	CentOS
	Debian
	Fedora
	Gentoo
	Mageia
	OpenSUSE
	PCLinuxOS
	Slackware
	Ubuntu
)

var distroNames = [...]string{
	Arch:      "Arch", // Manjaro
	CentOS:    "CentOS",
	Debian:    "Debian",
	Fedora:    "Fedora",
	Gentoo:    "Gentoo",
	Mageia:    "Mageia", // Mandriva fork
	OpenSUSE:  "openSUSE",
	PCLinuxOS: "PCLinuxOS",
	Slackware: "Slackware", // Slax
	Ubuntu:    "Ubuntu",
}

func (s Distro) String() string { return distroNames[s] }

var idToDistro = map[string]Distro{
	"arch":    Arch,
	"manjaro": Arch,

	"debian":    Debian,
	"fedora":    Fedora,
	"gentoo":    Gentoo,
	"mageia":    Mageia,
	"opensuse":  OpenSUSE,
	"slackware": Slackware,
	"ubuntu":    Ubuntu,
}

// Detect returns the Linux distribution.
func Detect() (Distro, error) {
	var id string
	var err error

	if _, err = os.Stat("/etc/os-release"); !os.IsNotExist(err) {
		cfg, err := shconf.ParseFile("/etc/os-release")
		if err != nil {
			return 0, err
		}

		if id, err = cfg.Get("ID"); err != nil {
			return 0, err
		}
		if v, found := idToDistro[id]; found {
			return v, nil
		}

	} else if _, err = os.Stat("/etc/centos-release"); !os.IsNotExist(err) {
		return CentOS, nil
	} else if _, err = os.Stat("/etc/pclinuxos-release"); !os.IsNotExist(err) {
		return PCLinuxOS, nil
	}

	panic("Linux distribution unsopported")
}
