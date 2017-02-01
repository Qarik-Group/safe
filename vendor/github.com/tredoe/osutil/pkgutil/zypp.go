// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pkgutil

import "github.com/tredoe/osutil"

type zypp struct{}

func (p zypp) Install(name ...string) error {
	args := []string{"install", "--auto-agree-with-licenses"}

	return osutil.Exec("/usr/bin/zypper", append(args, name...)...)
}

func (p zypp) Remove(name ...string) error {
	args := []string{"remove"}

	return osutil.Exec("/usr/bin/zypper", append(args, name...)...)
}

func (p zypp) Purge(name ...string) error {
	return p.Remove(name...)
}

func (p zypp) Update() error {
	return osutil.Exec("/usr/bin/zypper", "refresh")
}

func (p zypp) Upgrade() error {
	return osutil.Exec("/usr/bin/zypper", "up", "--auto-agree-with-licenses")
}

func (p zypp) Clean() error {
	return osutil.Exec("/usr/bin/zypper", "clean")
}
