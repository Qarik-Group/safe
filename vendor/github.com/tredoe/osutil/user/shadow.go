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
	"strconv"
	"strings"
	"time"
)

type shadowField int

// Field names for shadowed password database.
const (
	S_NAME shadowField = 1 << iota
	S_PASSWD
	S_CHANGED
	S_MIN
	S_MAX
	S_WARN
	S_INACTIVE
	S_EXPIRE
	S_FLAG

	S_ALL
)

func (f shadowField) String() string {
	switch f {
	case S_NAME:
		return "Name"
	case S_PASSWD:
		return "Passwd"
	case S_CHANGED:
		return "Changed"
	case S_MIN:
		return "Min"
	case S_MAX:
		return "Max"
	case S_WARN:
		return "Warn"
	case S_INACTIVE:
		return "Inactive"
	case S_EXPIRE:
		return "Expire"
	case S_FLAG:
		return "Flag"
	}
	return "ALL"
}

// changeType represents the options for last password change:
//
//   < 0: disable aging
//   0: change password
//   1: enable aging
//   > 1: number of days
type changeType int

const (
	_DISABLE_AGING changeType = -1 + iota
	_CHANGE_PASSWORD
	_ENABLE_AGING
)

func (c changeType) String() string {
	if c == _DISABLE_AGING {
		return ""
	}
	return strconv.Itoa(int(c))
}

func parseChange(s string) (changeType, error) {
	if s == "" {
		return _DISABLE_AGING, nil
	}
	i, err := strconv.Atoi(s)
	return changeType(i), err
}

// A Shadow represents the format of the information for a system's account and
// optional aging information.
//
// The fields "changed" and "expire" deal with days from Jan 1, 1970; but since
// package "time" deals with seconds, there is to divide it between the seconds
// that a day has (24*60*60) which is done by functions "setChange" and
// "SetExpire".
//
// To simulate an empty field in numeric fields, it is used a negative value.
type Shadow struct {
	// Login name. (Unique)
	//
	// It must be a valid account name, which exist on the system.
	Name string

	// Hashed password
	//
	// If the password field contains some string that is not a valid result of
	// crypt, for instance "!" or "*", the user will not be able to use a unix
	// password to log in (but the user may log in the system by other means).
	//
	// This field may be empty, in which case no passwords are required to
	// authenticate as the specified login name. However, some applications
	// which read the '/etc/shadow' file may decide not to permit any access at
	// all if the password field is empty.
	//
	// A password field which starts with a exclamation mark means that the
	// password is locked. The remaining characters on the line represent the
	// password field before the password was locked.
	password string

	// Date of last password change
	//
	// The date of the last password change, expressed as the number of days
	// since Jan 1, 1970.
	//
	// The value 0 has a special meaning, which is that the user should change
	// her pasword the next time he will log in the system.
	//
	// An empty field means that password aging features are disabled.
	changed changeType

	// Minimum password age
	//
	// The minimum password age is the number of days the user will have to wait
	// before he will be allowed to change her password again.
	//
	// An empty field and value 0 mean that there are no minimum password age.
	Min int

	// Maximum password age
	//
	// The maximum password age is the number of days after which the user will
	// have to change her password.
	//
	// After this number of days is elapsed, the password may still be valid.
	// The user should be asked to change her password the next time he will
	// log in.
	//
	// An empty field means that there are no maximum password age, no password
	// warning period, and no password inactivity period (see below).
	//
	// If the maximum password age is lower than the minimum password age, the
	// user cannot change her password.
	Max int

	// Password warning period
	//
	// The number of days before a password is going to expire (see the maximum
	// password age above) during which the user should be warned.
	//
	// An empty field and value 0 mean that there are no password warning period.
	Warn int

	// Password inactivity period
	//
	// The number of days after a password has expired (see the maximum password
	// age above) during which the password should still be accepted (and the
	// user should update her password during the next login).
	//
	// After expiration of the password and this expiration period is elapsed,
	// no login is possible using the current user's password.
	// The user should contact her administrator.
	//
	// An empty field means that there are no enforcement of an inactivity period.
	Inactive int

	// Account expiration date
	//
	// The date of expiration of the account, expressed as the number of days
	// since Jan 1, 1970.
	//
	// Note that an account expiration differs from a password expiration. In
	// case of an acount expiration, the user shall not be allowed to login. In
	// case of a password expiration, the user is not allowed to login using her
	// password.
	//
	// An empty field means that the account will never expire.
	//
	// The value 0 should not be used as it is interpreted as either an account
	// with no expiration, or as an expiration on Jan 1, 1970.
	expire int

	// Reserved field
	//
	// This field is reserved for future use.
	flag int
}

// NewShadow returns a structure Shadow with fields "Min", "Max" and "Warn"
// got from the system configuration, and enabling the features of password aging.
func NewShadow(username string) *Shadow {
	loadConfig()

	return &Shadow{
		Name:    username,
		changed: _ENABLE_AGING,
		Min:     config.login.PASS_MIN_DAYS,
		Max:     config.login.PASS_MAX_DAYS,
		Warn:    config.login.PASS_WARN_AGE,
	}
}

// setChange sets the date of the last password change to the current one.
func (s *Shadow) setChange() { s.changed = changeType(secToDay(time.Now().Unix())) }

// SetChangePasswd sets the account for that the user change her pasword the
// next time he will log in the system.
func (s *Shadow) SetChangePasswd() { s.changed = _CHANGE_PASSWORD }

// DisableAging disables the features of password aging.
func (s *Shadow) DisableAging() { s.changed = _DISABLE_AGING }

// EnableAging enables the features of password aging.
func (s *Shadow) EnableAging() { s.setChange() }

// SetExpire sets the date of expiration of the account.
func (s *Shadow) SetExpire(t *time.Time) { s.expire = secToDay(t.Unix()) }

func (s *Shadow) filename() string { return _SHADOW_FILE }

func (s *Shadow) String() string {
	var inactive, expire, flag string

	// Optional fields
	if s.Inactive != 0 {
		inactive = strconv.Itoa(s.Inactive)
	}
	if s.expire != 0 {
		expire = strconv.Itoa(s.expire)
	}
	if s.flag != 0 {
		flag = strconv.Itoa(s.flag)
	}

	return fmt.Sprintf("%s:%s:%s:%d:%d:%d:%s:%s:%s\n",
		s.Name, s.password, s.changed, s.Min, s.Max, s.Warn, inactive, expire, flag)
}

// parseShadow parses the row of a shadowed password.
func parseShadow(row string) (*Shadow, error) {
	fields := strings.Split(row, ":")
	if len(fields) != 9 {
		return nil, rowError{_SHADOW_FILE, row}
	}

	var inactive, expire, flag int

	changed, err := parseChange(fields[2])
	if err != nil {
		return nil, atoiError{_SHADOW_FILE, row, "changed"}
	}
	min, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil, atoiError{_SHADOW_FILE, row, "Min"}
	}
	max, err := strconv.Atoi(fields[4])
	if err != nil {
		return nil, atoiError{_SHADOW_FILE, row, "Max"}
	}
	warn, err := strconv.Atoi(fields[5])
	if err != nil {
		return nil, atoiError{_SHADOW_FILE, row, "Warn"}
	}

	// Optional fields

	if fields[6] != "" {
		if inactive, err = strconv.Atoi(fields[6]); err != nil {
			return nil, atoiError{_SHADOW_FILE, row, "Inactive"}
		}
	}
	if fields[7] != "" {
		if expire, err = strconv.Atoi(fields[7]); err != nil {
			return nil, atoiError{_SHADOW_FILE, row, "expire"}
		}
	}
	if fields[8] != "" {
		if flag, err = strconv.Atoi(fields[8]); err != nil {
			return nil, atoiError{_SHADOW_FILE, row, "flag"}
		}
	}

	return &Shadow{
		fields[0],
		fields[1],
		changed,
		min,
		max,
		warn,
		inactive,
		expire,
		flag,
	}, nil
}

// == Lookup
//

// lookUp parses the shadow passwd line searching a value into the field.
// Returns nil if is not found.
func (*Shadow) lookUp(line string, f field, value interface{}) interface{} {
	_field := f.(shadowField)
	allField := strings.Split(line, ":")
	intField := make(map[int]int)

	// Check integers
	changed, err := parseChange(allField[2])
	if err != nil {
		panic(atoiError{_SHADOW_FILE, line, "changed"})
	}
	if intField[3], err = strconv.Atoi(allField[3]); err != nil {
		panic(atoiError{_SHADOW_FILE, line, "Min"})
	}
	if intField[4], err = strconv.Atoi(allField[4]); err != nil {
		panic(atoiError{_SHADOW_FILE, line, "Max"})
	}
	if intField[5], err = strconv.Atoi(allField[5]); err != nil {
		panic(atoiError{_SHADOW_FILE, line, "Warn"})
	}
	// These fields could be empty.
	if allField[6] != "" {
		if intField[6], err = strconv.Atoi(allField[6]); err != nil {
			panic(atoiError{_SHADOW_FILE, line, "Inactive"})
		}
	}
	if allField[7] != "" {
		if intField[7], err = strconv.Atoi(allField[7]); err != nil {
			panic(atoiError{_SHADOW_FILE, line, "expire"})
		}
	}
	if allField[8] != "" {
		if intField[8], err = strconv.Atoi(allField[8]); err != nil {
			panic(atoiError{_SHADOW_FILE, line, "flag"})
		}
	}

	// Check fields
	var isField bool
	if S_NAME&_field != 0 && allField[0] == value.(string) {
		isField = true
	} else if S_PASSWD&_field != 0 && allField[1] == value.(string) {
		isField = true
	} else if S_CHANGED&_field != 0 && int(changed) == value.(int) {
		isField = true
	} else if S_MIN&_field != 0 && intField[3] == value.(int) {
		isField = true
	} else if S_MAX&_field != 0 && intField[4] == value.(int) {
		isField = true
	} else if S_WARN&_field != 0 && intField[5] == value.(int) {
		isField = true
	} else if S_INACTIVE&_field != 0 && intField[6] == value.(int) {
		isField = true
	} else if S_EXPIRE&_field != 0 && intField[7] == value.(int) {
		isField = true
	} else if S_FLAG&_field != 0 && intField[8] == value.(int) {
		isField = true
	} else if S_ALL&_field != 0 {
		isField = true
	}

	if isField {
		return &Shadow{
			allField[0],
			allField[1],
			changed,
			intField[3],
			intField[4],
			intField[5],
			intField[6],
			intField[7],
			intField[8],
		}
	}
	return nil
}

// LookupShadow looks for the entry for the given user name.
func LookupShadow(name string) (*Shadow, error) {
	entries, err := LookupInShadow(S_NAME, name, 1)
	if err != nil {
		return nil, err
	}

	return entries[0], err
}

// LookupInShadow looks up a shadowed password by the given values.
//
// The count determines the number of fields to return:
//   n > 0: at most n fields
//   n == 0: the result is nil (zero fields)
//   n < 0: all fields
func LookupInShadow(field shadowField, value interface{}, n int) ([]*Shadow, error) {
	checkRoot()

	iEntries, err := lookUp(&Shadow{}, field, value, n)
	if err != nil {
		return nil, err
	}

	// == Convert to type shadow
	valueSlice := reflect.ValueOf(iEntries)
	entries := make([]*Shadow, valueSlice.Len())

	for i := 0; i < valueSlice.Len(); i++ {
		entries[i] = valueSlice.Index(i).Interface().(*Shadow)
	}

	return entries, err
}

// == Editing
//

// Add adds a new shadowed user.
// If the key is not nil, generates a hashed password.
//
// It is created a backup before of modify the original file.
func (s *Shadow) Add(key []byte) (err error) {
	loadConfig()

	shadow, err := LookupShadow(s.Name)
	if err != nil {
		if _, ok := err.(NoFoundError); !ok {
			return
		}
	}
	if shadow != nil {
		return ErrUserExist
	}

	if s.Name == "" {
		return RequiredError("Name")
	}
	if s.Max == 0 {
		return RequiredError("Max")
	}
	if s.Warn == 0 {
		return RequiredError("Warn")
	}

	// Backup
	if err = backup(_SHADOW_FILE); err != nil {
		return
	}

	db, err := openDBFile(_SHADOW_FILE, os.O_WRONLY|os.O_APPEND)
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
		s.password, _ = config.crypter.Generate(key, nil)
		if s.changed == _ENABLE_AGING {
			s.setChange()
		}
	} else {
		s.password = "*" // Password disabled.
	}

	_, err = db.file.WriteString(s.String())
	return
}
