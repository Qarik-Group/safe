// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package shconf

import (
	"bufio"
	"bytes"
	"io"
	"strconv"
	"unicode"
	"unicode/utf8"
)

type extraCharError int

func (e extraCharError) Error() string {
	return strconv.Itoa(int(e)) + ": extra character/s after of the value"
}

type keyError int

func (e keyError) Error() string {
	return strconv.Itoa(int(e)) + ": key not found"
}

type noASCIIKeyError int

func (e noASCIIKeyError) Error() string {
	return strconv.Itoa(int(e)) + ": the key only must to have ASCII characters"
}

type openQuoteError int

func (e openQuoteError) Error() string {
	return strconv.Itoa(int(e)) + ": the quote in the value is not closed"
}

type valueError int

func (e valueError) Error() string {
	return strconv.Itoa(int(e)) + ": value not found"
}

// * * *

// _DEF_SEPARATOR is the character used like separator, by default.
var _DEF_SEPARATOR = []byte{'='}

// option represents the option to run the scanner.
type Option uint8

const (
	SKIP_KEYS_DISABLED Option = iota + 1
	GET_KEYS_DISABLED
)

// Scanner provides a convenient interface for reading data such as a file of
// lines of text in format key-value. Successive calls to the Scan method will
// step through the 'tokens' of a file, skipping the bytes between the tokens.
//
// Scanning stops unrecoverably at EOF, the first I/O error, or a token too
// large to fit in the buffer.
type Scanner struct {
	buf *bufio.Reader

	// Character/s used to separate the value from key.
	// It is only get in the first call to "Scan()".
	separator []byte

	key   []byte
	value []byte

	err  error
	line int // Number of line being scanned
}

// NewScanner returns a new Scanner to read from r, with the option to skip the
// keys disabled.
func NewScanner(r io.Reader) *Scanner { return &Scanner{buf: bufio.NewReader(r)} }

// Scan advances the Scanner to the next tokens, which will then be available
// through the Bytes or Text method. It returns false when the scan stops, either
// by reaching the end of the input or an error. After Scan returns false, the Err
// method will return any error that occurred during scanning, except that if it
// was io.EOF, Err will return nil.
func (s *Scanner) Scan() bool {
	var thisRune rune
	var n int
	var err error

	for s.line++; ; s.line++ {
		// Skip leading spaces.
		for thisRune, n, err = s.buf.ReadRune(); ; thisRune, _, err = s.buf.ReadRune() {
			if err != nil {
				s.err = err
				return false
			}

			if thisRune == '\n' {
				s.line++
				continue
			}
			if !unicode.IsSpace(thisRune) {
				break
			}
		}

		// Skip line comment and section.
		if thisRune == '#' || thisRune == '[' {
			if _, err = s.buf.ReadBytes('\n'); err != nil {
				s.err = err
				return false
			}
			continue
		}
		break
	}

	if thisRune == '=' {
		s.err = keyError(s.line)
		return false
	}

	var key, value, separator []rune

	// Get key

	for ; ; thisRune, n, err = s.buf.ReadRune() {
		if err != nil {
			if err != io.EOF {
				s.err = err
			} else {
				s.err = valueError(s.line)
			}
			return false
		}

		// The separator charater could the the equal sign or space.
		if thisRune == '=' || unicode.IsSpace(thisRune) {
			break
		}

		if n > 1 || !isValidChar(thisRune) {
			s.err = noASCIIKeyError(s.line)
			return false
		}
		key = append(key, thisRune)
	}

	// Skip spaces before and after of the separator character.

	if unicode.IsSpace(thisRune) {
		separator = append(separator, thisRune)

		for thisRune, _, err = s.buf.ReadRune(); ; thisRune, _, err = s.buf.ReadRune() {
			if err != nil {
				if err != io.EOF {
					s.err = err
				} else {
					s.err = valueError(s.line)
				}
				return false
			}

			if !unicode.IsSpace(thisRune) {
				break
			}
			separator = append(separator, thisRune)
		}
	}
	if thisRune == '=' {
		separator = append(separator, thisRune)

		if thisRune, _, err = s.buf.ReadRune(); err != nil {
			if err != io.EOF {
				s.err = err
			} else {
				s.err = valueError(s.line)
			}
			return false
		}
	}
	if unicode.IsSpace(thisRune) {
		separator = append(separator, thisRune)

		for thisRune, _, err = s.buf.ReadRune(); ; thisRune, _, err = s.buf.ReadRune() {
			if err != nil {
				if err != io.EOF {
					s.err = err
				} else {
					s.err = valueError(s.line)
				}
				return false
			}

			if !unicode.IsSpace(thisRune) {
				break
			}
			separator = append(separator, thisRune)
		}
	}

	// Get value

	var valueIsString, valueInDQuote bool
	var lastRune rune

	if thisRune == '"' { // The value is between double quotes
		valueIsString = true
		valueInDQuote = true
	} else if thisRune == '\'' { // between single quotes
		valueIsString = true
	} else {
		value = append(value, thisRune)
	}

	for thisRune, _, err = s.buf.ReadRune(); ; thisRune, _, err = s.buf.ReadRune() {
		if err != nil {
			if err != io.EOF {
				s.err = err
				return false
			}

			if valueIsString {
				s.err = openQuoteError(s.line)
				return false
			}
			s.err = err
			break
		}

		if valueIsString {
			if valueInDQuote {
				if thisRune == '"' && lastRune != '\\' {
					break
				}
			} else if thisRune == '\'' && lastRune != '\\' {
				break
			}
			lastRune = thisRune // To checking if it is a quote escaped.
			value = append(value, thisRune)

		} else {
			if unicode.IsSpace(thisRune) {
				break
			}
			value = append(value, thisRune)
		}
	}

	// Sanity check
	if thisRune != '\n' && thisRune != '\r' {
		doCheck := true
		last, _, err := s.buf.ReadLine()
		if err != nil {
			if err != io.EOF {
				s.err = err
				return false
			} else {
				doCheck = false
			}
		}

		if doCheck {
			for _, char := range last {
				if unicode.IsSpace(rune(char)) {
					continue
				} else if char == '#' {
					break
				} else {
					s.err = extraCharError(s.line)
					return false
				}
			}
		}
	}

	// Store key and value

	var bufKey, bufValue, bufSep bytes.Buffer
	var bytes []byte

	for _, r := range key {
		bytes = make([]byte, utf8.RuneLen(r))
		utf8.EncodeRune(bytes, r)
		bufKey.Write(bytes)
	}
	s.key = bufKey.Bytes()

	for _, r := range value {
		bytes = make([]byte, utf8.RuneLen(r))
		utf8.EncodeRune(bytes, r)
		bufValue.Write(bytes)
	}
	s.value = bufValue.Bytes()

	// Store separator character
	if s.separator == nil {
		for _, r := range separator {
			bytes = make([]byte, utf8.RuneLen(r))
			utf8.EncodeRune(bytes, r)
			bufSep.Write(bytes)
		}
		s.separator = bufSep.Bytes()
	}

	return true
}

// Bytes returns the most recents tokens generated by a call to Scan. The
// underlying array may point to data that will be overwritten by a subsequent
// call to Scan. It does no allocation.
func (s *Scanner) Bytes() (key, value []byte) { return s.key, s.value }

// Text returns the most recents tokens generated by a call to Scan as a newly
// allocated string holding its bytes.
func (s *Scanner) Text() (key, value string) {
	return string(s.key), string(s.value)
}

// Err returns the first non-EOF error that was encountered by the Scanner.
func (s *Scanner) Err() error {
	if s.err != io.EOF {
		return s.err
	}
	return nil
}

// Separator returns the character/s used to separate the key from the value.
//
// The separator is got in the first call to "Scan()"; if it has not been
// called, this makes it explicitly but panics when there is any error.
func (s *Scanner) Separator() []byte {
	if s.separator == nil {
		if found := s.Scan(); !found {
			if err := s.Err(); err != nil {
				panic(err)
			}
			return _DEF_SEPARATOR
		}
	}
	return s.separator
}

// == Utility

func isValidChar(r rune) bool {
	if (r < 'A' || r > 'Z') /*&& r < 'a' && r > 'z'*/ && r != '_' {
		return false
	}
	return true
}
