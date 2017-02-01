// Copyright 2010 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"fmt"
	"os"
	"reflect"
	"strings"
)

type gshadowField int

// Field names for shadowed group database.
const (
	GS_NAME gshadowField = 1 << iota
	GS_PASSWD
	GS_ADMIN
	GS_MEMBER

	GS_ALL
)

func (f gshadowField) String() string {
	switch f {
	case GS_NAME:
		return "Name"
	case GS_PASSWD:
		return "Passwd"
	case GS_ADMIN:
		return "Admin"
	case GS_MEMBER:
		return "Member"
	}
	return "ALL"
}

// A GShadow represents the format of the shadowed information for a group account.
type GShadow struct {
	// Group name. (Unique)
	//
	// It must be a valid group name, which exist on the system.
	Name string

	// Hashed password
	//
	// If the password field contains some string that is not a valid result of
	// crypt, for instance "!" or "*", users will not be able to use a unix
	// password to access the group (but group members do not need the password).
	//
	// The password is used when an user who is not a member of the group wants
	// to gain the permissions of this group (see "newgrp(1)").
	//
	// This field may be empty, in which case only the group members can gain
	// the group permissions.
	//
	// A password field which starts with a exclamation mark means that the
	// password is locked. The remaining characters on the line represent the
	// password field before the password was locked.
	//
	// This password supersedes any password specified in '/etc/group'.
	password string

	// Group administrator list
	//
	// It must be a comma-separated list of user names.
	//
	// Administrators can change the password or the members of the group.
	// Administrators also have the same permissions as the members (see below).
	AdminList []string

	// Group member list
	//
	// It must be a comma-separated list of user names.
	//
	// Members can access the group without being prompted for a password.
	// You should use the same list of users as in /etc/group.
	UserList []string
}

// NewGShadow returns a new GShadow.
func NewGShadow(username string, members ...string) *GShadow {
	return &GShadow{
		Name:     username,
		UserList: members,
	}
}

func (gs *GShadow) filename() string { return _GSHADOW_FILE }

func (gs *GShadow) String() string {
	return fmt.Sprintf("%s:%s:%s:%s\n",
		gs.Name, gs.password, strings.Join(gs.AdminList, ","), strings.Join(gs.UserList, ","))
}

// parseGShadow parses the row of a group shadow.
func parseGShadow(row string) (*GShadow, error) {
	fields := strings.Split(row, ":")
	if len(fields) != 4 {
		return nil, rowError{_GSHADOW_FILE, row}
	}

	return &GShadow{
		fields[0],
		fields[1],
		strings.Split(fields[2], ","),
		strings.Split(fields[3], ","),
	}, nil
}

// == Lookup
//

// lookUp parses the shadowed group line searching a value into the field.
// Returns nil if it isn't found.
func (*GShadow) lookUp(line string, f field, value interface{}) interface{} {
	_field := f.(gshadowField)
	_value := value.(string)
	allField := strings.Split(line, ":")
	arrayField := make(map[int][]string)

	arrayField[2] = strings.Split(allField[2], ",")
	arrayField[3] = strings.Split(allField[3], ",")

	// Check fields
	var isField bool
	if GS_NAME&_field != 0 && allField[0] == _value {
		isField = true
	} else if GS_PASSWD&_field != 0 && allField[1] == _value {
		isField = true
	} else if GS_ADMIN&_field != 0 && checkGroup(arrayField[2], _value) {
		isField = true
	} else if GS_MEMBER&_field != 0 && checkGroup(arrayField[3], _value) {
		isField = true
	} else if GS_ALL&_field != 0 {
		isField = true
	}

	if isField {
		return &GShadow{
			allField[0],
			allField[1],
			arrayField[2],
			arrayField[3],
		}
	}
	return nil
}

// LookupGShadow looks up a shadowed group by name.
func LookupGShadow(name string) (*GShadow, error) {
	entries, err := LookupInGShadow(GS_NAME, name, 1)
	if err != nil {
		return nil, err
	}

	return entries[0], err
}

// LookupInGShadow looks up a shadowed group by the given values.
//
// The count determines the number of fields to return:
//   n > 0: at most n fields
//   n == 0: the result is nil (zero fields)
//   n < 0: all fields
func LookupInGShadow(field gshadowField, value string, n int) ([]*GShadow, error) {
	checkRoot()

	iEntries, err := lookUp(&GShadow{}, field, value, n)
	if err != nil {
		return nil, err
	}

	// == Convert to type GShadow
	valueSlice := reflect.ValueOf(iEntries)
	entries := make([]*GShadow, valueSlice.Len())

	for i := 0; i < valueSlice.Len(); i++ {
		entries[i] = valueSlice.Index(i).Interface().(*GShadow)
	}

	return entries, err
}

// == Editing
//

// Add adds a new shadowed group.
// If the key is not nil, generates a hashed password.
//
// It is created a backup before of modify the original file.
func (gs *GShadow) Add(key []byte) (err error) {
	loadConfig()

	gshadow, err := LookupGShadow(gs.Name)
	if err != nil {
		if _, ok := err.(NoFoundError); !ok {
			return
		}
	}
	if gshadow != nil {
		return ErrGroupExist
	}

	if gs.Name == "" {
		return RequiredError("Name")
	}

	// Backup
	if err = backup(_GSHADOW_FILE); err != nil {
		return
	}

	db, err := openDBFile(_GSHADOW_FILE, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return
	}
	defer func() {
		e := db.close()
		if e != nil && err == nil {
			err = e
		}
	}()

	if key != nil {
		gs.password, _ = config.crypter.Generate(key, nil)
	} else {
		gs.password = "*" // Password disabled.
	}

	_, err = db.file.WriteString(gs.String())
	return
}
