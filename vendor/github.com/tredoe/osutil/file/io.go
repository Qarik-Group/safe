// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Copy copies file in source to file in dest preserving the mode attributes.
func Copy(source, dest string) (err error) {
	// Don't backup files of backup.
	if dest[len(dest)-1] != '~' {
		if err = Backup(dest); err != nil {
			return
		}
	}

	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() {
		err2 := srcFile.Close()
		if err2 != nil && err == nil {
			err = err2
		}
	}()

	srcInfo, err := os.Stat(source)
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode().Perm())
	if err != nil {
		return err
	}

	_, err = io.Copy(dstFile, srcFile)
	err2 := dstFile.Close()
	if err2 != nil && err == nil {
		err = err2
	}
	return
}

// Create creates a new file with b bytes.
func Create(filename string, b []byte) (err error) {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	_, err = file.Write(b)
	err2 := file.Close()
	if err2 != nil && err == nil {
		err = err2
	}
	return
}

// CreateString is like Create, but writes the contents of string s rather than
// an array of bytes.
func CreateString(filename, s string) error {
	return Create(filename, []byte(s))
}

// Overwrite truncates the named file to zero and writes len(b) bytes. It
// returns an error, if any.
func Overwrite(filename string, b []byte) (err error) {
	if err := Backup(filename); err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	_, err = file.Write(b)
	err2 := file.Close()
	if err2 != nil && err == nil {
		err = err2
	}
	return
}

// OverwriteString is like Overwrite, but writes the contents of string s rather
// than an array of bytes.
func OverwriteString(filename, s string) error {
	return Overwrite(filename, []byte(s))
}

// == Utility

const _BACKUP_SUFFIX = "+[1-9]~" // Suffix pattern added to backup's file name.

const PREFIX_TEMP = "test-" // Prefix to add to temporary files.

// Backup creates a backup of the named file.
//
// The schema used for the new name is: {name}\+[1-9]~
//   name: The original file name.
//   + : Character used to separate the file name from rest.
//   number: A number from 1 to 9, using rotation.
//   ~ : To indicate that it is a backup, just like it is used in Unix systems.
func Backup(filename string) error {
	// Check if it is empty
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() == 0 {
		return nil
	}

	files, err := filepath.Glob(filename + _BACKUP_SUFFIX)
	if err != nil {
		return err
	}

	// Number rotation
	numBackup := byte(1)

	if len(files) != 0 {
		lastFile := files[len(files)-1]
		numBackup = lastFile[len(lastFile)-2] + 1 // next number

		if numBackup > '9' {
			numBackup = '1'
		}
	} else {
		numBackup = '1'
	}

	return Copy(filename, fmt.Sprintf("%s+%s~", filename, string(numBackup)))
}

// CopytoTemp creates a temporary file from the source file into the default
// directory for temporary files (see os.TempDir), whose name begins with prefix.
// If prefix is the empty string, uses the default value PREFIX_TEMP.
// Returns the temporary file name.
func CopytoTemp(source, prefix string) (tmpFile string, err error) {
	if prefix == "" {
		prefix = PREFIX_TEMP
	}

	src, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer func() {
		err2 := src.Close()
		if err2 != nil && err == nil {
			err = err2
		}
	}()

	dest, err := ioutil.TempFile("", prefix)
	if err != nil {
		return "", err
	}
	defer func() {
		err2 := dest.Close()
		if err2 != nil && err == nil {
			err = err2
		}
	}()

	if _, err = io.Copy(dest, src); err != nil {
		return "", err
	}
	return dest.Name(), nil
}
