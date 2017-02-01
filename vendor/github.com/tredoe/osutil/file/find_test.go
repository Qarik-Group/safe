// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import "testing"

func TestFind(t *testing.T) {
	ok, err := ContainString(TEMP_FILE, "night")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("ContainString: expected %t, found %t", !ok, ok)
	}

	ok, err = Contain(TEMP_FILE, []byte("night"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("Contain: expected %t, found %t", !ok, ok)
	}
}
