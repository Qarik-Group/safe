// Copyright 2010 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"bufio"
	"io"
	"os"
	"testing"
)

func TestShadowParser(t *testing.T) {
	f, err := os.Open(_SHADOW_FILE)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	buf := bufio.NewReader(f)

	for {
		line, _, err := buf.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Error(err)
			continue
		}

		if _, err = parseShadow(string(line)); err != nil {
			t.Error(err)
		}
	}
}

func TestShadowFull(t *testing.T) {
	entry, err := LookupShadow("root")
	if err != nil || entry == nil {
		t.Error(err)
	}

	entries, err := LookupInShadow(S_PASSWD, "!", -1)
	if err != nil || entries == nil {
		t.Error(err)
	}

	entries, err = LookupInShadow(S_ALL, nil, -1)
	if err != nil || len(entries) == 0 {
		t.Error(err)
	}
}

func TestShadowCount(t *testing.T) {
	count := 2
	entries, err := LookupInShadow(S_MIN, 0, count)
	if err != nil || len(entries) != count {
		t.Error(err)
	}

	count = 5
	entries, err = LookupInShadow(S_ALL, nil, count)
	if err != nil || len(entries) != count {
		t.Error(err)
	}
}

func TestShadowError(t *testing.T) {
	_, err := LookupShadow("!!!???")
	if _, ok := err.(NoFoundError); !ok {
		t.Error("expected to report NoFoundError")
	}

	if _, err = LookupInShadow(S_MIN, 0, 0); err != errSearch {
		t.Error("expected to report errSearch")
	}

	s := &Shadow{}
	if err = s.Add(nil); err != RequiredError("Name") {
		t.Error("expected to report RequiredError")
	}
}

func TestShadow_Add(t *testing.T) {
	shadow := NewShadow(USER)
	err := shadow.Add(nil)
	if err != nil {
		t.Fatal(err)
	}

	if err = shadow.Add(nil); err == nil {
		t.Fatal("a shadowed user existent can not be added again")
	} else {
		if !IsExist(err) {
			t.Error("shadow: expected to report ErrExist")
		}
	}

	s, err := LookupShadow(USER)
	if err != nil {
		t.Fatal(err)
	}

	if s.Name != USER {
		t.Errorf("shadow: expected to get name %q", USER)
	}
}

var (
	USER_KEY1 = []byte("123")
	USER_KEY2 = []byte("456")
)

func TestShadowCrypt(t *testing.T) {
	s, err := LookupShadow(USER)
	if err != nil {
		t.Fatal(err)
	}
	s.Passwd(USER_KEY1)
	if err = config.crypter.Verify(s.password, USER_KEY1); err != nil {
		t.Fatalf("expected to get the same hashed password for %q", USER_KEY1)
	}

	if err = ChPasswd(USER, USER_KEY2); err != nil {
		t.Fatalf("expected to change password: %s", err)
	}
	s, _ = LookupShadow(USER)
	if err = config.crypter.Verify(s.password, USER_KEY2); err != nil {
		t.Fatalf("ChPasswd: expected to get the same hashed password for %q", USER_KEY2)
	}
}
