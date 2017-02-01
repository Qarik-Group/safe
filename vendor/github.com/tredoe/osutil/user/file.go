// Copyright 2010 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/tredoe/osutil/file"
)

// A row represents the structure of a row into a file.
type row interface {
	// lookUp is the parser to looking for a value in the field of given line.
	lookUp(line string, _field field, value interface{}) interface{}

	// filename returns the file name belongs to the file structure.
	filename() string

	String() string
}

// A field represents a field into a row.
type field interface {
	String() string
}

var errSearch = errors.New("no search")

// lookUp is a generic parser to looking for a value.
//
// The count determines the number of fields to return:
//   n > 0: at most n fields
//   n == 0: the result is nil (zero fields)
//   n < 0: all fields
func lookUp(_row row, _field field, value interface{}, n int) (interface{}, error) {
	if n == 0 {
		return nil, errSearch
	}

	dbf, err := openDBFile(_row.filename(), os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer dbf.close()

	// Lines where a field is matched.
	entries := make([]interface{}, 0, 0)

	for {
		line, _, err := dbf.rd.ReadLine()
		if err == io.EOF {
			break
		}

		entry := _row.lookUp(string(line), _field, value)
		if entry != nil {
			entries = append(entries, entry)
		}

		if n < 0 {
			continue
		} else if n == len(entries) {
			break
		}
	}

	if len(entries) != 0 {
		return entries, nil
	}
	return nil, NoFoundError{_row.filename(), _field.String(), value}
}

// == Editing
//

// DO_BACKUP does a backup before of modify the original files.
var DO_BACKUP = true

// A dbfile represents the database file.
type dbfile struct {
	sync.Mutex
	file *os.File
	rd   *bufio.Reader
}

// openDBFile opens a file.
func openDBFile(filename string, flag int) (*dbfile, error) {
	f, err := os.OpenFile(filename, flag, 0)
	if err != nil {
		return nil, err
	}

	db := &dbfile{file: f, rd: bufio.NewReader(f)}
	db.Lock()
	return db, nil
}

// close closes the file.
func (db *dbfile) close() error {
	db.Unlock()
	return db.file.Close()
}

// _FILES_BACKUPED are the files that already have been backuped.
var _FILES_BACKUPED = make(map[string]struct{}, 4)

// backup does a backup of a file.
func backup(filename string) error {
	if DO_BACKUP {
		if _, ok := _FILES_BACKUPED[filename]; !ok {
			if err := file.Backup(filename); err != nil {
				return err
			}
			_FILES_BACKUPED[filename] = struct{}{}
		}
	}
	return nil
}

func edit(name string, r row) error { return _edit(name, r, false) }

func del(name string, r row) error { return _edit(name, r, true) }

// _edit is a generic editor for the given user/group name.
// If remove is true, it removes the structure of the user/group name.
//
// TODO: get better performance if start to store since when the file is edited.
// So there is to store the size of all lines read until that point to seek from
// there.
func _edit(name string, _row row, remove bool) (err error) {
	filename := _row.filename()

	dbf, err := openDBFile(filename, os.O_RDWR)
	if err != nil {
		return err
	}
	defer func() {
		e := dbf.close()
		if e != nil && err == nil {
			err = e
		}
	}()

	var buf bytes.Buffer
	name_b := []byte(name)
	isFound := false

	for {
		line, err2 := dbf.rd.ReadBytes('\n')
		if err2 == io.EOF {
			break
		}

		if !isFound && bytes.HasPrefix(line, name_b) {
			isFound = true
			if remove { // skip user
				continue
			}

			line = []byte(_row.String())
		}
		if _, err = buf.Write(line); err != nil {
			return err
		}
	}

	if isFound {
		if err = backup(filename); err != nil {
			return
		}

		if _, err = dbf.file.Seek(0, os.SEEK_SET); err != nil {
			return
		}

		var n int
		n, err = dbf.file.Write(buf.Bytes())
		if err != nil {
			return
		}
		err = dbf.file.Truncate(int64(n))
	}

	return
}
