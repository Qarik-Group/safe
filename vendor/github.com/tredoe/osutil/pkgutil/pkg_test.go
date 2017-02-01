// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pkgutil

import "testing"

func TestPackager(t *testing.T) {
	pkg, err := Detect()
	if err != nil {
		t.Fatal(err)
	}
	pack := New(pkg)
	cmd := "curl"

	if err = pack.Update(); err != nil {
		t.Fatal(err)
	}
	if err = pack.Upgrade(); err != nil {
		t.Fatal(err)
	}

	if err = pack.Install(cmd); err != nil {
		t.Errorf("\n%s", err)
	}
	if err = pack.Remove(cmd); err != nil {
		t.Errorf("\n%s", err)
	}

	if err = pack.Clean(); err != nil {
		t.Errorf("\n%s", err)
	}
}
