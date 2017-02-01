// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"fmt"
	"testing"
)

// TestAddGroup add a new group, so the next GIDs will have a value greater than
// in the systems file.

func TestID(t *testing.T) {
	id, err := NextSystemUID()
	if err != nil {
		t.Error(err)
	}
	if testing.Verbose() {
		fmt.Print(" Next system UID: ", id)
	}

	if id, err = NextUID(); err != nil {
		t.Error(err)
	}
	if testing.Verbose() {
		fmt.Println("\tNext UID:", id)
	}

	if id, err = NextSystemGID(); err != nil {
		t.Error(err)
	}
	if testing.Verbose() {
		fmt.Print(" Next system GID: ", id)
	}

	if id, err = NextGID(); err != nil {
		t.Error(err)
	}
	if testing.Verbose() {
		fmt.Println("\tNext GID:", id)
	}
}
