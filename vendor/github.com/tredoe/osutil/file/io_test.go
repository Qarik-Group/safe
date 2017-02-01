// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupSuffix(t *testing.T) {
	okFilenames := []string{"foo+1~", "foo+2~", "foo+5~", "foo+8~", "foo+9~"}
	badFilenames := []string{"foo+0~", "foo+10~", "foo+11~", "foo+22~"}

	for _, v := range okFilenames {
		ok, err := filepath.Match("foo"+_BACKUP_SUFFIX, v)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("expected to not match %q", v)
		}
	}

	for _, v := range badFilenames {
		ok, err := filepath.Match("foo"+_BACKUP_SUFFIX, v)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("expected to not match %q", v)
		}
	}
}

const FILENAME = "doc.go"

func TestCopytoTemp(t *testing.T) {
	name, err := CopytoTemp(FILENAME, "")
	if err != nil {
		t.Fatal(err)
	}
	checkCopytoTemp(name, PREFIX_TEMP, t)

	name, err = CopytoTemp(FILENAME, "foo-")
	if err != nil {
		t.Fatal(err)
	}
	checkCopytoTemp(name, "foo-", t)
}

func checkCopytoTemp(filename, prefix string, t *testing.T) {
	if prefix == "" {
		prefix = PREFIX_TEMP
	}
	if !strings.HasPrefix(filename, filepath.Join(os.TempDir(), prefix)) {
		t.Error("got wrong prefix")
	}

	if err := os.Remove(filename); err != nil {
		t.Error(err)
	}
}
