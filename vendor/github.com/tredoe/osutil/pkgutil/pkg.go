// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package pkgutil handles basic operations in the management of packages in
// operating systems.
//
// Important
//
// If you are going to use a package manager different to Deb, then you should
// check the options since I cann't test all.
//
// TODO
//
// Add managers of BSD systems.
//
// Use flag to do not show questions.
package pkgutil

import (
	"errors"
	"os/exec"
)

// Packager is the common interface to handle different package systems.
type Packager interface {
	// Install installs packages.
	Install(name ...string) error

	// Remove removes packages.
	Remove(name ...string) error

	// Purge removes packages and its configuration files.
	Purge(name ...string) error

	// Update resynchronizes the package index files from their sources.
	Update() error

	// Upgrade upgrades all the packages on the system.
	Upgrade() error

	// Clean erases both packages downloaded and orphaned dependencies.
	Clean() error
}

// PackageType represents a package management system.
type PackageType int8

const (
	// Linux
	Deb PackageType = iota + 1
	RPM
	Pacman
	Ebuild
	ZYpp
)

func (pkg PackageType) String() string {
	switch pkg {
	case Deb:
		return "Deb"
	case RPM:
		return "RPM"
	case Pacman:
		return "Pacman"
	case Ebuild:
		return "Ebuild"
	case ZYpp:
		return "ZYpp"
	}
	panic("unreachable")
}

// New returns the interface to handle the package manager.
func New(pkg PackageType) Packager {
	switch pkg {
	case Deb:
		return new(deb)
	case RPM:
		return new(rpm)
	case Pacman:
		return new(pacman)
	case Ebuild:
		return new(ebuild)
	case ZYpp:
		return new(zypp)
	}
	panic("unreachable")
}

// execPackagers is a list of executables of package managers.
var execPackagers = [...]string{
	Deb:    "apt-get",
	RPM:    "yum",
	Pacman: "pacman",
	Ebuild: "emerge",
	ZYpp:   "zypper",
}

// Detect tries to get the package system used in the system, looking for
// executables in directory "/usr/bin".
func Detect() (PackageType, error) {
	for k, v := range execPackagers {
		_, err := exec.LookPath("/usr/bin/" + v)
		if err == nil {
			return PackageType(k), nil
		}
	}
	return -1, errors.New("package manager not found in directory '/usr/bin'")
}
