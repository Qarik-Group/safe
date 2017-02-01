// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import (
	"os"
	"path/filepath"
)

var (
	TEMP_FILE   = filepath.Join(os.TempDir(), "test-file.txt")
	TEMP_BACKUP = TEMP_FILE + "+1~"
)
