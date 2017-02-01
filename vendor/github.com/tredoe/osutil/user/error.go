// Copyright 2010 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"errors"
	"fmt"
	"strconv"
)

var (
	ErrUserExist  = errors.New("user already exists")
	ErrGroupExist = errors.New("group already exists")
)

// IsExist returns whether the error is known to report that an user or group
// already exists. It is satisfied by ErrUserExist and ErrGroupExist.
func IsExist(err error) bool {
	if err == ErrUserExist || err == ErrGroupExist {
		return true
	}
	return false
}

// An IdUsedError reports the presence of an identifier already used.
type IdUsedError int

func (e IdUsedError) Error() string { return "id used: " + strconv.Itoa(int(e)) }

// A NoFoundError reports the absence of a value.
type NoFoundError struct {
	file  string
	field string
	value interface{}
}

func (e NoFoundError) Error() string {
	return fmt.Sprintf("entry \"%v\" not found: file '%s', field %q",
		e.value, e.file, e.field)
}

// A RequiredError reports the name of a required field.
type RequiredError string

func (e RequiredError) Error() string { return "required field: " + string(e) }

// An atoiError records the file, row and field that caused the error at turning
// a field from string to int.
type atoiError struct {
	file  string
	row   string
	field string
}

func (e atoiError) Error() string {
	return fmt.Sprintf("field %q on '%s' could not be turned to int\n%s",
		e.field, e.file, e.row)
}

// A rowError records the file and row for a format not valid.
type rowError struct {
	file string
	row  string
}

func (e rowError) Error() string {
	return fmt.Sprintf("format of row not valid on '%s'\n%s", e.file, e.row)
}
