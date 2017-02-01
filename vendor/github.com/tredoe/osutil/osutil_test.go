// Copyright 2014 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package osutil

import (
	"testing"
)

func TestSudo(t *testing.T) {
	if err := Sudo(); err != nil {
		t.Error(err)
	}
}
