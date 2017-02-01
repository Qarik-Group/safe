// Copyright 2010 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"io"
	"os"
	"strconv"
)

// nextUID returns the next free user id to use, according to whether it is a
// system's user.
func nextUID(isSystem bool) (db *dbfile, uid int, err error) {
	loadConfig()

	db, err = openDBFile(_USER_FILE, os.O_RDWR)
	if err != nil {
		return
	}

	// Seek to file half size.

	info, err := db.file.Stat()
	if err != nil {
		db.close()
		return nil, 0, err
	}
	if _, err = db.file.Seek(info.Size()/2, os.SEEK_SET); err != nil {
		db.close()
		return nil, 0, err
	}
	// To starting to read from a new line
	if _, _, err = db.rd.ReadLine(); err != nil {
		db.close()
		return nil, 0, err
	}

	var minUid, maxUid int
	if isSystem {
		minUid, maxUid = config.login.SYS_UID_MIN, config.login.SYS_UID_MAX
	} else {
		minUid, maxUid = config.login.UID_MIN, config.login.UID_MAX
	}

	for {
		line, _, err := db.rd.ReadLine()
		if err == io.EOF {
			break
		}

		u, err := parseUser(string(line))
		if err != nil {
			db.close()
			return nil, 0, err
		}
		if u.UID >= minUid && u.UID <= maxUid {
			uid = u.UID
		}
	}

	uid++
	if uid == maxUid {
		return nil, 0, &IdRangeError{maxUid, isSystem, true}
	}
	return
}

// nextGUID returns the next free group id to use, according to whether it is a
// system's group.
func nextGUID(isSystem bool) (db *dbfile, gid int, err error) {
	loadConfig()

	db, err = openDBFile(_GROUP_FILE, os.O_RDWR)
	if err != nil {
		return
	}

	// Seek to file half size.

	info, err := db.file.Stat()
	if err != nil {
		db.close()
		return nil, 0, err
	}
	if _, err = db.file.Seek(info.Size()/2, os.SEEK_SET); err != nil {
		db.close()
		return nil, 0, err
	}
	// To starting to read from a new line
	if _, _, err = db.rd.ReadLine(); err != nil {
		db.close()
		return nil, 0, err
	}

	var minGid, maxGid int
	if isSystem {
		minGid, maxGid = config.login.SYS_GID_MIN, config.login.SYS_GID_MAX
	} else {
		minGid, maxGid = config.login.GID_MIN, config.login.GID_MAX
	}

	for {
		line, _, err := db.rd.ReadLine()
		if err == io.EOF {
			break
		}

		gr, err := parseGroup(string(line))
		if err != nil {
			db.close()
			return nil, 0, err
		}
		if gr.GID >= minGid && gr.GID <= maxGid {
			gid = gr.GID
		}
	}

	gid++
	if gid == maxGid {
		return nil, 0, &IdRangeError{maxGid, isSystem, false}
	}
	return
}

// NextSystemUID returns the next free system user id to use.
func NextSystemUID() (int, error) {
	db, uid, err := nextUID(true)
	db.close()
	return uid, err
}

// NextSystemGID returns the next free system group id to use.
func NextSystemGID() (int, error) {
	db, gid, err := nextGUID(true)
	db.close()
	return gid, err
}

// NextUID returns the next free user id to use.
func NextUID() (int, error) {
	db, uid, err := nextUID(false)
	db.close()
	return uid, err
}

// NextGID returns the next free group id to use.
func NextGID() (int, error) {
	db, gid, err := nextGUID(false)
	db.close()
	return gid, err
}

// * * *

// An IdRangeError records an error during the search for a free id to use.
type IdRangeError struct {
	LastId   int
	IsSystem bool
	IsUser   bool
}

func (e *IdRangeError) Error() string {
	str := ""
	if e.IsSystem {
		str = "system "
	}
	if e.IsUser {
		str += "user: "
	} else {
		str += "group: "
	}
	str += strconv.Itoa(e.LastId)

	return "reached maximum identifier in " + str
}
