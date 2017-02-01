// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import (
	"testing"
)

func TestInfo(t *testing.T) {
	ok, err := IsDir("../file")
	if err != nil {
		t.Error(err)
	} else if !ok {
		t.Error("IsDir got false")
	}

	fi, err := NewInfo("info.go")
	if err != nil {
		t.Fatal(err)
	}

	if !fi.OwnerHas(R, W) {
		t.Error("OwnerHas(R,W) got false")
	}
	if fi.OwnerHas(X) {
		t.Error("OwnerHas(X) got true")
	}
}
