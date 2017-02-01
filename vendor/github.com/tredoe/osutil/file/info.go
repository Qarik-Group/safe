// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import "os"

// flags got in: `man 2 stat`
const (
	modeROwner = 00400 // owner has read permission
	modeWOwner = 00200 // owner has write permission
	modeXOwner = 00100 // owner has execute permission

	modeRGroup = 00040 // group has read permission
	modeWGroup = 00020 // group has write permission
	modeXGroup = 00010 // group has execute permission

	modeROthers = 00004 // others have read permission
	modeWOthers = 00002 // others have write permission
	modeXOthers = 00001 // others have execute permission
)

type perm uint8

// permissions
const (
	_ perm = iota
	R      // read
	W      // write
	X      // execute
)

// info represents a wrapper about os.FileInfo to append some functions.
type info struct{ fi os.FileInfo }

// NewInfo returns a info describing the named file.
func NewInfo(name string) (*info, error) {
	i, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	return &info{i}, nil
}

// IsDir reports whether if it is a directory.
func (i *info) IsDir() bool {
	return i.fi.IsDir()
}

// IsFile reports whether it is a regular file.
func (i *info) IsFile() bool {
	return i.fi.Mode()&os.ModeType == 0
}

// OwnerHas reports whether the owner has all given permissions.
func (i *info) OwnerHas(p ...perm) bool {
	mode := i.fi.Mode()

	for _, v := range p {
		switch v {
		case R:
			if mode&modeROwner == 0 {
				return false
			}
		case W:
			if mode&modeWOwner == 0 {
				return false
			}
		case X:
			if mode&modeXOwner == 0 {
				return false
			}
		}
	}
	return true
}

// GroupHas reports whether the group has all given permissions.
func (i *info) GroupHas(p ...perm) bool {
	mode := i.fi.Mode()

	for _, v := range p {
		switch v {
		case R:
			if mode&modeRGroup == 0 {
				return false
			}
		case W:
			if mode&modeWGroup == 0 {
				return false
			}
		case X:
			if mode&modeXGroup == 0 {
				return false
			}
		}
	}
	return true
}

// OthersHave reports whether the others have all given permissions.
func (i *info) OthersHave(p ...perm) bool {
	mode := i.fi.Mode()

	for _, v := range p {
		switch v {
		case R:
			if mode&modeROthers == 0 {
				return false
			}
		case W:
			if mode&modeWOthers == 0 {
				return false
			}
		case X:
			if mode&modeXOthers == 0 {
				return false
			}
		}
	}
	return true
}

// * * *

// IsDir reports whether if the named file is a directory.
func IsDir(name string) (bool, error) {
	i, err := NewInfo(name)
	if err != nil {
		return false, err
	}
	return i.IsDir(), nil
}

// IsFile reports whether the named file is a regular file.
func IsFile(name string) (bool, error) {
	i, err := NewInfo(name)
	if err != nil {
		return false, err
	}
	return i.IsFile(), nil
}

// OwnerHas reports whether the named file has all given permissions for the owner.
func OwnerHas(name string, p ...perm) (bool, error) {
	i, err := NewInfo(name)
	if err != nil {
		return false, err
	}
	return i.OwnerHas(p...), nil
}

// GroupHas reports whether the named file has all given permissions for the group.
func GroupHas(name string, p ...perm) (bool, error) {
	i, err := NewInfo(name)
	if err != nil {
		return false, err
	}
	return i.GroupHas(p...), nil
}

// OthersHave reports whether the named file have all given permissions for the others.
func OthersHave(name string, p ...perm) (bool, error) {
	i, err := NewInfo(name)
	if err != nil {
		return false, err
	}
	return i.OthersHave(p...), nil
}
