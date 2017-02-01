// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"os"
	"path/filepath"

	"github.com/tredoe/goutil"
	"github.com/tredoe/osutil"
	"github.com/tredoe/osutil/file"
)

const (
	USER     = "u_foo"
	USER2    = "u_foo2"
	SYS_USER = "usys_bar"

	GROUP     = "g_foo"
	SYS_GROUP = "gsys_bar"
)

var MEMBERS = []string{USER, SYS_USER}

// Stores the ids at creating the groups.
var GID, SYS_GID int

// == Copy the system files before of be edited.

func init() {
	err := osutil.MustbeRoot()
	if err != nil {
		goutil.Fatalf("%s", err)
	}

	if _USER_FILE, err = file.CopytoTemp(_USER_FILE, "test-user_"); err != nil {
		goto _error
	}
	if _GROUP_FILE, err = file.CopytoTemp(_GROUP_FILE, "test-group_"); err != nil {
		goto _error
	}
	if _SHADOW_FILE, err = file.CopytoTemp(_SHADOW_FILE, "test-shadow_"); err != nil {
		goto _error
	}
	if _GSHADOW_FILE, err = file.CopytoTemp(_GSHADOW_FILE, "test-gshadow_"); err != nil {
		goto _error
	}

	return

_error:
	removeTempFiles()
	goutil.Fatalf("%s", err)
}

func removeTempFiles() {
	files, _ := filepath.Glob(filepath.Join(os.TempDir(), file.PREFIX_TEMP+"*"))

	for _, f := range files {
		if err := os.Remove(f); err != nil {
			goutil.Errorf("%s", err)
		}
	}
}
