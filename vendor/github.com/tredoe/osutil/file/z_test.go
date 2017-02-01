// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import (
	"os"
	"testing"
)

func Test_z(t *testing.T) {
	if err := os.Remove(TEMP_FILE); err != nil {
		t.Error(err)
	}
}
