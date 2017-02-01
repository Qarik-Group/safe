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

func TestGroupParser(t *testing.T) {
	f, err := os.Open(_GROUP_FILE)
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

		if _, err = parseGroup(string(line)); err != nil {
			t.Error(err)
		}
	}
}

func TestGroupFull(t *testing.T) {
	entry, err := LookupGID(os.Getgid())
	if err != nil || entry == nil {
		t.Error(err)
	}

	entry, err = LookupGroup("root")
	if err != nil || entry == nil {
		t.Error(err)
	}

	entries, err := LookupInGroup(G_MEMBER, "", -1)
	if err != nil || entries == nil {
		t.Error(err)
	}

	entries, err = LookupInGroup(G_ALL, nil, -1)
	if err != nil || len(entries) == 0 {
		t.Error(err)
	}
}

func TestGroupCount(t *testing.T) {
	count := 5
	entries, err := LookupInGroup(G_ALL, nil, count)
	if err != nil || len(entries) != count {
		t.Error(err)
	}
}

func TestGroupError(t *testing.T) {
	_, err := LookupGroup("!!!???")
	if _, ok := err.(NoFoundError); !ok {
		t.Error("expected to report NoFoundError")
	}

	if _, err = LookupInGroup(G_MEMBER, "", 0); err != errSearch {
		t.Error("expected to report errSearch")
	}

	g := &Group{}
	if _, err = g.Add(); err != RequiredError("Name") {
		t.Error("expected to report RequiredError")
	}
}

func TestGetGroups(t *testing.T) {
	gids := Getgroups()
	gnames := GetgroupsName()

	for i, gid := range gids {
		g, err := LookupGID(gid)
		if err != nil {
			t.Error(err)
		}

		if g.Name != gnames[i] {
			t.Errorf("expected to match GID and group name")
		}
	}
}

func TestGroup_Add(t *testing.T) {
	group := NewGroup(GROUP, MEMBERS...)
	_testGroup_Add(t, group, MEMBERS, false)

	group = NewSystemGroup(SYS_GROUP, MEMBERS...)
	_testGroup_Add(t, group, MEMBERS, true)
}

func _testGroup_Add(t *testing.T, group *Group, members []string, ofSystem bool) {
	prefix := "group"
	if ofSystem {
		prefix = "system " + prefix
	}

	id, err := group.Add()
	if err != nil {
		t.Fatal(err)
	}
	if id == -1 {
		t.Errorf("%s: got UID = -1", prefix)
	}

	if _, err = group.Add(); err == nil {
		t.Fatalf("%s: an existent group can not be added again", prefix)
	} else {
		if !IsExist(err) {
			t.Errorf("%s: expected to report ErrExist", prefix)
		}
	}

	if ofSystem {
		if !group.IsOfSystem() {
			t.Errorf("%s: IsOfSystem(): expected true")
		}
	} else {
		if group.IsOfSystem() {
			t.Errorf("%s: IsOfSystem(): expected false")
		}
	}

	// Check value stored

	name := ""
	if ofSystem {
		name = SYS_GROUP
	} else {
		name = GROUP
	}

	g, err := LookupGroup(name)
	if err != nil {
		t.Fatalf("%s: ", err)
	}

	if g.Name != name {
		t.Errorf("%s: expected to get name %q", prefix, name)
	}
	if g.UserList[0] != members[0] || g.UserList[1] != members[1] {
		t.Error("%s: expected to get members: %s", prefix, g.UserList)
	}
}

func TestGroup_Members(t *testing.T) {
	group := "g1"
	member := "m0"

	_, err := AddGroup(group, MEMBERS...)
	if err != nil {
		t.Fatal(err)
	}

	g_first, err := LookupGroup(group)
	if err != nil {
		t.Fatal(err)
	}
	sg_first, err := LookupGShadow(group)
	if err != nil {
		t.Fatal(err)
	}

	err = AddUsersToGroup(group, member)
	if err != nil {
		t.Fatal(err)
	}

	g_last, err := LookupGroup(group)
	if err != nil {
		t.Fatal(err)
	}
	sg_last, err := LookupGShadow(group)
	if err != nil {
		t.Fatal(err)
	}

	if len(g_first.UserList) == len(g_last.UserList) ||
		g_last.UserList[0] != USER ||
		g_last.UserList[1] != SYS_USER ||
		g_last.UserList[2] != member {
		t.Error("group file: expected to add users into a group")
	}
	if len(sg_first.UserList) == len(sg_last.UserList) ||
		sg_last.UserList[0] != USER ||
		sg_last.UserList[1] != SYS_USER ||
		sg_last.UserList[2] != member {
		t.Error("gshadow file: expected to add users into a group")
	}

	// == Delete

	err = DelUsersInGroup(group, member, USER)
	if err != nil {
		t.Fatal(err)
	}

	g_del, err := LookupGroup(group)
	if err != nil {
		t.Fatal(err)
	}
	sg_del, err := LookupGShadow(group)
	if err != nil {
		t.Fatal(err)
	}

	if len(g_del.UserList) == len(g_last.UserList) ||
		g_del.UserList[0] != SYS_USER {
		t.Error("group file: expected to remove members of a group")
	}
	if len(sg_del.UserList) == len(sg_last.UserList) ||
		sg_del.UserList[0] != SYS_USER {
		t.Error("gshadow file: expected to remove members of a group")
	}
}
