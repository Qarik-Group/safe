// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pkgutil

import "github.com/tredoe/osutil"

type deb struct{}

func (p deb) Install(name ...string) error {
	args := []string{"install", "-y"}

	return osutil.ExecSudo("/usr/bin/apt-get", append(args, name...)...)
}

func (p deb) Remove(name ...string) error {
	args := []string{"remove", "-y"}

	return osutil.ExecSudo("/usr/bin/apt-get", append(args, name...)...)
}

func (p deb) Purge(name ...string) error {
	args := []string{"purge", "-y"}

	return osutil.ExecSudo("/usr/bin/apt-get", append(args, name...)...)
}

func (p deb) Update() error {
	return osutil.ExecSudo("/usr/bin/apt-get", "update", "-qq")
}

func (p deb) Upgrade() error {
	return osutil.ExecSudo("/usr/bin/apt-get", "upgrade")
}

func (p deb) Clean() error {
	err := osutil.ExecSudo("/usr/bin/apt-get", "autoremove", "-y")
	if err != nil {
		return err
	}

	return osutil.ExecSudo("/usr/bin/apt-get", "clean")
}
