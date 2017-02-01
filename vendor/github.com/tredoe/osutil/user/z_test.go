// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import "testing"

func TestDelUser(t *testing.T) {
	err := DelUser(USER)
	if err != nil {
		t.Fatal(err)
	}

	_, err = LookupUser(USER)
	if _, ok := err.(NoFoundError); !ok {
		t.Error("expected to get error NoFoundError")
	}
	_, err = LookupShadow(USER)
	if _, ok := err.(NoFoundError); !ok {
		t.Error("expected to get error NoFoundError")
	}
}

func TestDelGroup(t *testing.T) {
	err := DelGroup(GROUP)
	if err != nil {
		t.Fatal(err)
	}

	_, err = LookupGroup(GROUP)
	if _, ok := err.(NoFoundError); !ok {
		t.Error("expected to get error NoFoundError")
	}
	_, err = LookupGShadow(GROUP)
	if _, ok := err.(NoFoundError); !ok {
		t.Error("expected to get error NoFoundError")
	}
}

func TestZ(*testing.T) {
	removeTempFiles()
}
