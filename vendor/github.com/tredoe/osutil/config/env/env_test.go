// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package env

import "testing"

func TestCheckKey(t *testing.T) {
	caught := false

	defer func() {
		if x := recover(); x != nil {
			if x != errKey {
				t.Fatal("expected to get error: errKey")
			}
			caught = true
		}
	}()

	goodKey := "FOO_BAR"
	checkKey(goodKey)
	if caught == true {
		t.Fatalf("expected to don't get a call to panic with key %q", goodKey)
	}

	badKey := goodKey + "_a"
	checkKey(badKey)
	if caught == false {
		t.Fatalf("expected to get a call to panic with key %q", badKey)
	}
}
