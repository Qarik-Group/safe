// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"regexp"
)

// editDefault represents the vaues by default to set in type edit.
type editDefault struct {
	CommentChar string // character used in comments
	//DoBackup    bool   // do backup before of edit?
}

// Values by default for type edit.
var _editDefault = editDefault{"#"}

// edit represents the file to edit.
type edit struct {
	editDefault
	file *os.File
	buf  *bufio.ReadWriter
}

type Replacer struct {
	Search, Replace string
}

type ReplacerAtLine struct {
	Line, Search, Replace string
}

// NewEdit opens a file to edit; it is created a backup.
func NewEdit(filename string) (*edit, error) {
	if err := Backup(filename); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(filename, os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}

	return &edit{
		_editDefault,
		file,
		bufio.NewReadWriter(bufio.NewReader(file), bufio.NewWriter(file)),
	}, nil
}

// Append writes len(b) bytes at the end of the File. It returns an error, if any.
func (e *edit) Append(b []byte) error {
	_, err := e.file.Seek(0, os.SEEK_END)
	if err != nil {
		return err
	}

	_, err = e.file.Write(b)
	return err
}

// AppendString is like Append, but writes the contents of string s rather than
// an array of bytes.
func (e *edit) AppendString(s string) error {
	return e.Append([]byte(s))
}

// Close closes the file.
func (e *edit) Close() error {
	return e.file.Close()
}

// Comment inserts the comment character in lines that mach any regular expression
// in reLine.
func (e *edit) Comment(reLine []string) error {
	allReSearch := make([]*regexp.Regexp, len(reLine))

	for i, v := range reLine {
		if re, err := regexp.Compile(v); err != nil {
			return err
		} else {
			allReSearch[i] = re
		}
	}

	if _, err := e.file.Seek(0, os.SEEK_SET); err != nil {
		return err
	}

	char := []byte(e.CommentChar + " ")
	isNew := false
	buf := new(bytes.Buffer)

	// Check every line.
	for {
		line, err := e.buf.ReadBytes('\n')
		if err == io.EOF {
			break
		}

		for _, v := range allReSearch {
			if v.Match(line) {
				line = append(char, line...)

				if !isNew {
					isNew = true
				}
				break
			}
		}

		if _, err = buf.Write(line); err != nil {
			return err
		}
	}

	if isNew {
		return e.rewrite(buf.Bytes())
	}
	return nil
}

// CommentOut removes the comment character of lines that mach any regular expression
// in reLine.
func (e *edit) CommentOut(reLine []string) error {
	allSearch := make([]ReplacerAtLine, len(reLine))

	for i, v := range reLine {
		allSearch[i] = ReplacerAtLine{
			v,
			"[[:space:]]*" + e.CommentChar + "[[:space:]]*",
			"",
		}
	}

	return e.ReplaceAtLineN(allSearch, 1)
}

/*// Insert writes len(b) bytes at the start of the File. It returns an error, if any.
func (e *edit) Insert(b []byte) error {
	return e.rewrite(b)
}

// InsertString is like Insert, but writes the contents of string s rather than
// an array of bytes.
func (e *edit) InsertString(s string) error {
	return e.rewrite([]byte(s))
}*/

// Replace replaces all regular expressions mathed in r.
func (e *edit) Replace(r []Replacer) error {
	return e.genReplace(r, -1)
}

// ReplaceN replaces regular expressions mathed in r. The count determines the
// number to match:
//   n > 0: at most n matches
//   n == 0: the result is none
//   n < 0: all matches
func (e *edit) ReplaceN(r []Replacer, n int) error {
	return e.genReplace(r, n)
}

// ReplaceAtLine replaces all regular expressions mathed in r, if the line is
// matched at the first.
func (e *edit) ReplaceAtLine(r []ReplacerAtLine) error {
	return e.genReplaceAtLine(r, -1)
}

// ReplaceAtLine replaces regular expressions mathed in r, if the line is
// matched at the first. The count determines the
// number to match:
//   n > 0: at most n matches
//   n == 0: the result is none
//   n < 0: all matches
func (e *edit) ReplaceAtLineN(r []ReplacerAtLine, n int) error {
	return e.genReplaceAtLine(r, n)
}

// Generic Replace: replaces a number of regular expressions matched in r.
func (e *edit) genReplace(r []Replacer, n int) error {
	if n == 0 {
		return nil
	}
	if _, err := e.file.Seek(0, os.SEEK_SET); err != nil {
		return err
	}

	content, err := ioutil.ReadAll(e.buf)
	if err != nil {
		return err
	}

	isNew := false

	for _, v := range r {
		reSearch, err := regexp.Compile(v.Search)
		if err != nil {
			return err
		}

		i := n
		repl := []byte(v.Replace)

		content = reSearch.ReplaceAllFunc(content, func(s []byte) []byte {
			if !isNew {
				isNew = true
			}

			if i != 0 {
				i--
				return repl
			}
			return s
		})
	}

	if isNew {
		return e.rewrite(content)
	}
	return nil
}

// Generic ReplaceAtLine: replaces a number of regular expressions matched in r,
// if the line is matched at the first.
func (e *edit) genReplaceAtLine(r []ReplacerAtLine, n int) error {
	if n == 0 {
		return nil
	}
	if _, err := e.file.Seek(0, os.SEEK_SET); err != nil {
		return err
	}

	// == Cache the regular expressions
	allReLine := make([]*regexp.Regexp, len(r))
	allReSearch := make([]*regexp.Regexp, len(r))
	allRepl := make([][]byte, len(r))

	for i, v := range r {
		if reLine, err := regexp.Compile(v.Line); err != nil {
			return err
		} else {
			allReLine[i] = reLine
		}

		if reSearch, err := regexp.Compile(v.Search); err != nil {
			return err
		} else {
			allReSearch[i] = reSearch
		}

		allRepl[i] = []byte(v.Replace)
	}

	buf := new(bytes.Buffer)
	isNew := false

	// Replace every line, if it maches
	for {
		line, err := e.buf.ReadBytes('\n')
		if err == io.EOF {
			break
		}

		for i, _ := range r {
			if allReLine[i].Match(line) {
				j := n

				line = allReSearch[i].ReplaceAllFunc(line, func(s []byte) []byte {
					if !isNew {
						isNew = true
					}

					if j != 0 {
						j--
						return allRepl[i]
					}
					return s
				})
			}
		}
		if _, err = buf.Write(line); err != nil {
			return err
		}
	}

	if isNew {
		return e.rewrite(buf.Bytes())
	}
	return nil
}

func (e *edit) rewrite(b []byte) error {
	if _, err := e.file.Seek(0, os.SEEK_SET); err != nil {
		return err
	}

	n, err := e.file.Write(b)
	if err != nil {
		return err
	}
	if err = e.file.Truncate(int64(n)); err != nil {
		return err
	}
	return nil // e.file.Sync()
}

// * * *

// Append writes len(b) bytes at the end of the named file. It returns an
// error, if any. The file is backed up.
func Append(filename string, b []byte) error {
	e, err := NewEdit(filename)
	if err != nil {
		return err
	}

	err = e.Append(b)
	err2 := e.Close()
	if err != nil {
		return err
	}
	return err2
}

// AppendString is like Append, but writes the contents of string s rather than
// an array of bytes.
func AppendString(filename, s string) error {
	return Append(filename, []byte(s))
}

// Comment inserts the comment character in lines that mach the regular expression
// in reLine, in the named file.
func Comment(filename, reLine string) error {
	return CommentM(filename, []string{reLine})
}

// CommentM inserts the comment character in lines that mach any regular expression
// in reLine, in the named file.
func CommentM(filename string, reLine []string) error {
	e, err := NewEdit(filename)
	if err != nil {
		return err
	}

	err = e.Comment(reLine)
	err2 := e.Close()
	if err != nil {
		return err
	}
	return err2
}

// CommentOut removes the comment character of lines that mach the regular expression
// in reLine, in the named file.
func CommentOut(filename, reLine string) error {
	return CommentOutM(filename, []string{reLine})
}

// CommentOutM removes the comment character of lines that mach any regular expression
// in reLine, in the named file.
func CommentOutM(filename string, reLine []string) error {
	e, err := NewEdit(filename)
	if err != nil {
		return err
	}

	err = e.CommentOut(reLine)
	err2 := e.Close()
	if err != nil {
		return err
	}
	return err2
}

/*// Insert writes len(b) bytes at the start of the named file. It returns an
// error, if any. The file is backed up.
func Insert(filename string, b []byte) error {
	e, err := NewEdit(filename)
	if err != nil {
		return err
	}

	err = e.Insert(b)
	err2 := e.Close()
	if err != nil {
		return err
	}
	return err2
}

// InsertString is like Insert, but writes the contents of string s rather than
// an array of bytes.
func InsertString(filename, s string) error {
	return Insert(filename, []byte(s))
}*/

// Replace replaces all regular expressions mathed in r for the named file.
func Replace(filename string, r []Replacer) error {
	e, err := NewEdit(filename)
	if err != nil {
		return err
	}

	err = e.genReplace(r, -1)
	err2 := e.Close()
	if err != nil {
		return err
	}
	return err2
}

// ReplaceN replaces a number of regular expressions mathed in r for the named
// file.
func ReplaceN(filename string, r []Replacer, n int) error {
	e, err := NewEdit(filename)
	if err != nil {
		return err
	}

	err = e.genReplace(r, n)
	err2 := e.Close()
	if err != nil {
		return err
	}
	return err2
}

// ReplaceAtLine replaces all regular expressions mathed in r for the named
// file, if the line is matched at the first.
func ReplaceAtLine(filename string, r []ReplacerAtLine) error {
	e, err := NewEdit(filename)
	if err != nil {
		return err
	}

	err = e.genReplaceAtLine(r, -1)
	err2 := e.Close()
	if err != nil {
		return err
	}
	return err2
}

// ReplaceAtLineN replaces a number of regular expressions mathed in r for the
// named file, if the line is matched at the first.
func ReplaceAtLineN(filename string, r []ReplacerAtLine, n int) error {
	e, err := NewEdit(filename)
	if err != nil {
		return err
	}

	err = e.genReplaceAtLine(r, n)
	err2 := e.Close()
	if err != nil {
		return err
	}
	return err2
}
