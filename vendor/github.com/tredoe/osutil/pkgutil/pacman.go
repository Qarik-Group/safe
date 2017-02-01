// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pkgutil

import "github.com/tredoe/osutil"

type pacman struct{}

func (p pacman) Install(name ...string) error {
	args := []string{"-S", "--needed", "--noprogressbar"}

	return osutil.Exec("/usr/bin/pacman", append(args, name...)...)
}

func (p pacman) Remove(name ...string) error {
	args := []string{"-Rs"}

	return osutil.Exec("/usr/bin/pacman", append(args, name...)...)
}

func (p pacman) Purge(name ...string) error {
	args := []string{"-Rsn"}

	return osutil.Exec("/usr/bin/pacman", append(args, name...)...)
}

func (p pacman) Update() error {
	return osutil.Exec("/usr/bin/pacman", "-Syu", "--needed", "--noprogressbar")
}

func (p pacman) Upgrade() error {
	return osutil.Exec("/usr/bin/pacman", "-Syu")
}

func (p pacman) Clean() error {
	return osutil.Exec("/usr/bin/paccache", "-r")
}
