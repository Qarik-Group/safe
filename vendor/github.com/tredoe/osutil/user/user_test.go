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

func TestUserParser(t *testing.T) {
	f, err := os.Open(_USER_FILE)
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

		if _, err = parseUser(string(line)); err != nil {
			t.Error(err)
		}
	}
}

func TestUserFull(t *testing.T) {
	entry, err := LookupUID(os.Getuid())
	if err != nil || entry == nil {
		t.Error(err)
	}

	entry, err = LookupUser("root")
	if err != nil || entry == nil {
		t.Error(err)
	}

	entries, err := LookupInUser(U_GID, 65534, -1)
	if err != nil || entries == nil {
		t.Error(err)
	}

	entries, err = LookupInUser(U_GECOS, "", -1)
	if err != nil || entries == nil {
		t.Error(err)
	}

	entries, err = LookupInUser(U_DIR, "/bin", -1)
	if err != nil || entries == nil {
		t.Error(err)
	}

	entries, err = LookupInUser(U_SHELL, "/bin/false", -1)
	if err != nil || entries == nil {
		t.Error(err)
	}

	entries, err = LookupInUser(U_ALL, nil, -1)
	if err != nil || len(entries) == 0 {
		t.Error(err)
	}
}

func TestUserCount(t *testing.T) {
	count := 2
	entries, err := LookupInUser(U_SHELL, "/bin/false", count)
	if err != nil || len(entries) != count {
		t.Error(err)
	}

	count = 5
	entries, err = LookupInUser(U_ALL, nil, count)
	if err != nil || len(entries) != count {
		t.Error(err)
	}
}

func TestUserError(t *testing.T) {
	_, err := LookupUser("!!!???")
	if _, ok := err.(NoFoundError); !ok {
		t.Error("expected to report NoFoundError")
	}

	if _, err = LookupInUser(U_SHELL, "/bin/false", 0); err != errSearch {
		t.Error("expected to report errSearch")
	}

	u := &User{}
	if _, err = u.Add(); err != RequiredError("Name") {
		t.Error("expected to report RequiredError")
	}

	u = &User{Name: USER, Dir: config.useradd.HOME, Shell: config.useradd.SHELL}
	if _, err = u.Add(); err != HomeError(config.useradd.HOME) {
		t.Error("expected to report HomeError")
	}
}

func TestUser_Add(t *testing.T) {
	user := NewUser(USER, GID)
	user.Dir = "/tmp"
	_testUser_Add(t, user, false)

	user = NewSystemUser(SYS_USER, "/tmp", GID)
	_testUser_Add(t, user, true)
}

func _testUser_Add(t *testing.T, user *User, ofSystem bool) {
	prefix := "user"
	if ofSystem {
		prefix = "system " + prefix
	}

	id, err := user.Add()
	if err != nil {
		t.Fatal(err)
	}
	if id == -1 {
		t.Errorf("%s: got UID = -1", prefix)
	}

	if _, err = user.Add(); err == nil {
		t.Fatalf("%s: an existent user can not be added again", prefix)
	} else {
		if !IsExist(err) {
			t.Errorf("%s: expected to report ErrExist", prefix)
		}
	}

	if ofSystem {
		if !user.IsOfSystem() {
			t.Errorf("%s: IsOfSystem(): expected true")
		}
	} else {
		if user.IsOfSystem() {
			t.Errorf("%s: IsOfSystem(): expected false")
		}
	}

	// Check value stored

	name := ""
	if ofSystem {
		name = SYS_USER
	} else {
		name = USER
	}

	u, err := LookupUser(name)
	if err != nil {
		t.Fatalf("%s: ", err)
	}

	if u.Name != name {
		t.Errorf("%s: expected to get name %q", prefix, name)
	}
}

func TestUserLock(t *testing.T) {
	err := LockUser(USER)
	if err != nil {
		t.Fatal(err)
	}
	s, err := LookupShadow(USER)
	if err != nil {
		t.Fatal(err)
	}
	if s.password[0] != _LOCK_CHAR {
		t.Fatalf("expected to get password starting with '%c', got: '%c'",
			_LOCK_CHAR, s.password[0])
	}

	err = UnlockUser(USER)
	if err != nil {
		t.Fatal(err)
	}
	s, err = LookupShadow(USER)
	if err != nil {
		t.Fatal(err)
	}
	if s.password[0] == _LOCK_CHAR {
		t.Fatalf("no expected to get password starting with '%c'", _LOCK_CHAR)
	}
}
