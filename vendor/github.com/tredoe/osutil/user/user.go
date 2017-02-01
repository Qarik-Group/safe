// Copyright 2010 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"fmt"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"
)

type userField int

// Field names for user database.
const (
	U_NAME userField = 1 << iota
	U_PASSWD
	U_UID
	U_GID
	U_GECOS
	U_DIR
	U_SHELL

	U_ALL // To get lines without searching into a field.
)

func (f userField) String() string {
	switch f {
	case U_NAME:
		return "Name"
	case U_PASSWD:
		return "Passwd"
	case U_UID:
		return "UID"
	case U_GID:
		return "GID"
	case U_GECOS:
		return "GECOS"
	case U_DIR:
		return "Dir"
	case U_SHELL:
		return "Shell"
	}
	return "ALL"
}

// An User represents an user account.
type User struct {
	// Login name. (Unique)
	Name string

	// Optional hashed password
	//
	// The hashed password field may be blank, in which case no password is
	// required to authenticate as the specified login name. However, some
	// applications which read the '/etc/passwd' file may decide not to permit
	// any access at all if the password field is blank. If the password field
	// is a lower-case "x", then the encrypted password is actually stored in
	// the "shadow(5)" file instead; there must be a corresponding line in the
	// '/etc/shadow' file, or else the user account is invalid. If the password
	// field is any other string, then it will be treated as an hashed password,
	// as specified by "crypt(3)".
	password string

	// Numerical user ID. (Unique)
	UID int

	// Numerical group ID
	GID int

	// User name or comment field
	//
	// The comment field is used by various system utilities, such as "finger(1)".
	Gecos string

	// User home directory
	//
	// The home directory field provides the name of the initial working
	// directory. The login program uses this information to set the value of
	// the $HOME environmental variable.
	Dir string

	// Optional user command interpreter
	//
	// The command interpreter field provides the name of the user's command
	// language interpreter, or the name of the initial program to execute.
	// The login program uses this information to set the value of the "$SHELL"
	// environmental variable. If this field is empty, it defaults to the value
	// "/bin/sh".
	Shell string

	addSystemUser bool
}

// NewUser returns a new User with both fields "Dir" and "Shell" got from
// the system configuration.
func NewUser(name string, gid int) *User {
	loadConfig()

	return &User{
		Name:  name,
		Dir:   path.Join(config.useradd.HOME, name),
		Shell: config.useradd.SHELL,
		UID:   -1,
		GID:   gid,
	}
}

// NewSystemUser returns a new system user.
func NewSystemUser(name, homeDir string, gid int) *User {
	return &User{
		Name:  name,
		Dir:   homeDir,
		Shell: "/bin/false",
		UID:   -1,
		GID:   gid,

		addSystemUser: true,
	}
}

func (u *User) filename() string { return _USER_FILE }

// IsOfSystem indicates whether it is a system user.
func (u *User) IsOfSystem() bool {
	//loadConfig()

	if u.UID > config.login.SYS_UID_MIN && u.UID < config.login.SYS_UID_MAX {
		return true
	}
	return false
}

func (u *User) String() string {
	return fmt.Sprintf("%s:%s:%d:%d:%s:%s:%s\n",
		u.Name, u.password, u.UID, u.GID, u.Gecos, u.Dir, u.Shell)
}

// parseUser parses the row of an user.
func parseUser(row string) (*User, error) {
	fields := strings.Split(row, ":")
	if len(fields) != 7 {
		return nil, rowError{_USER_FILE, row}
	}

	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, atoiError{_USER_FILE, row, "UID"}
	}
	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil, atoiError{_USER_FILE, row, "GID"}
	}

	return &User{
		Name:     fields[0],
		password: fields[1],
		UID:      uid,
		GID:      gid,
		Gecos:    fields[4],
		Dir:      fields[5],
		Shell:    fields[6],
	}, nil
}

// == Lookup
//

// lookUp parses the user line searching a value into the field.
// Returns nil if is not found.
func (*User) lookUp(line string, f field, value interface{}) interface{} {
	_field := f.(userField)
	allField := strings.Split(line, ":")
	intField := make(map[int]int)

	// Check integers
	var err error
	if intField[2], err = strconv.Atoi(allField[2]); err != nil {
		panic(atoiError{_USER_FILE, line, "UID"})
	}
	if intField[3], err = strconv.Atoi(allField[3]); err != nil {
		panic(atoiError{_USER_FILE, line, "GID"})
	}

	// Check fields
	var isField bool
	if U_NAME&_field != 0 && allField[0] == value.(string) {
		isField = true
	} else if U_PASSWD&_field != 0 && allField[1] == value.(string) {
		isField = true
	} else if U_UID&_field != 0 && intField[2] == value.(int) {
		isField = true
	} else if U_GID&_field != 0 && intField[3] == value.(int) {
		isField = true
	} else if U_GECOS&_field != 0 && allField[4] == value.(string) {
		isField = true
	} else if U_DIR&_field != 0 && allField[5] == value.(string) {
		isField = true
	} else if U_SHELL&_field != 0 && allField[6] == value.(string) {
		isField = true
	} else if U_ALL&_field != 0 {
		isField = true
	}

	if isField {
		return &User{
			Name:     allField[0],
			password: allField[1],
			UID:      intField[2],
			GID:      intField[3],
			Gecos:    allField[4],
			Dir:      allField[5],
			Shell:    allField[6],
		}
	}
	return nil
}

// LookupUID looks up an user by user ID.
func LookupUID(uid int) (*User, error) {
	entries, err := LookupInUser(U_UID, uid, 1)
	if err != nil {
		return nil, err
	}

	return entries[0], err
}

// LookupUser looks up an user by name.
func LookupUser(name string) (*User, error) {
	entries, err := LookupInUser(U_NAME, name, 1)
	if err != nil {
		return nil, err
	}

	return entries[0], err
}

// LookupInUser looks up an user by the given values.
//
// The count determines the number of fields to return:
//   n > 0: at most n fields
//   n == 0: the result is nil (zero fields)
//   n < 0: all fields
func LookupInUser(field userField, value interface{}, n int) ([]*User, error) {
	iEntries, err := lookUp(&User{}, field, value, n)
	if err != nil {
		return nil, err
	}

	// == Convert to type user
	valueSlice := reflect.ValueOf(iEntries)
	entries := make([]*User, valueSlice.Len())

	for i := 0; i < valueSlice.Len(); i++ {
		entries[i] = valueSlice.Index(i).Interface().(*User)
	}

	return entries, err
}

// GetUsername returns the user name from the password database for the actual
// process.
// It panics whther there is an error at searching the UID.
func GetUsername() string {
	entry, err := LookupUID(os.Getuid())
	if err != nil {
		panic(err)
	}
	return entry.Name
}

// GetUsernameFromEnv returns the user name from the environment variable
// for the actual process.
func GetUsernameFromEnv() string {
	user_env := []string{"USER", "USERNAME", "LOGNAME", "LNAME"}

	for _, val := range user_env {
		name := os.Getenv(val)
		if name != "" {
			return name
		}
	}
	return ""
}

// == Editing
//

// AddUser adds an user to both user and shadow files.
func AddUser(name string, gid int) (uid int, err error) {
	s := NewShadow(name)
	if err = s.Add(nil); err != nil {
		return
	}

	return NewUser(name, gid).Add()
}

// AddSystemUser adds a system user to both user and shadow files.
func AddSystemUser(name, homeDir string, gid int) (uid int, err error) {
	s := NewShadow(name)
	if err = s.Add(nil); err != nil {
		return
	}

	return NewSystemUser(name, homeDir, gid).Add()
}

// Add adds a new user.
// Whether UID is < 0, it will choose the first id available in the range set
// in the system configuration.
func (u *User) Add() (uid int, err error) {
	loadConfig()

	user, err := LookupUser(u.Name)
	if err != nil {
		if _, ok := err.(NoFoundError); !ok {
			return
		}
	}
	if user != nil {
		return 0, ErrUserExist
	}

	if u.Name == "" {
		return 0, RequiredError("Name")
	}
	if u.Dir == "" {
		return 0, RequiredError("Dir")
	}
	if u.Dir == config.useradd.HOME {
		return 0, HomeError(config.useradd.HOME)
	}
	if u.Shell == "" {
		return 0, RequiredError("Shell")
	}

	var db *dbfile
	if u.UID < 0 {
		db, uid, err = nextUID(u.addSystemUser)
		if err != nil {
			db.close()
			return 0, err
		}
		u.UID = uid
	} else {
		db, err = openDBFile(_USER_FILE, os.O_WRONLY|os.O_APPEND)
		if err != nil {
			return 0, err
		}

		// Check if Id is unique.
		_, err = LookupUID(u.UID)
		if err == nil {
			return 0, IdUsedError(u.UID)
		} else if _, ok := err.(NoFoundError); !ok {
			return 0, err
		}
	}

	u.password = "x"

	_, err = db.file.WriteString(u.String())
	err2 := db.close()
	if err2 != nil && err == nil {
		err = err2
	}
	return
}

// DelUser removes an user from the system.
func DelUser(name string) (err error) {
	err = del(name, &User{})
	if err == nil {
		err = del(name, &Shadow{})
	}
	return
}

// == Errors
//

// A HomeError reports an error at adding an account with invalid home directory.
type HomeError string

func (e HomeError) Error() string {
	return "invalid directory for the home directory of an account: " + string(e)
}
