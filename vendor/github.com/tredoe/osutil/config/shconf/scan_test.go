// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package shconf

import (
	"bytes"
	"testing"
)

var scanTests = []struct {
	in    string
	key   string
	value string
}{
	{" \n  # qwe", "", ""},
	{" \n  [ qwe ]\n ABC=def", "ABC", "def"},
	{" \n  # qwe \n ABC=def", "ABC", "def"},
	{"ABC=def", "ABC", "def"},
	{" ABC = def ", "ABC", "def"},
	{" \n FOO=bar ", "FOO", "bar"}, // 5
	{`FOO="bar"`, "FOO", "bar"},
	{"FOO='bar'", "FOO", "bar"},
}

func TestScanKeys(t *testing.T) {
	for n, test := range scanTests {
		s := NewScanner(bytes.NewBufferString(test.in))
		s.Scan()
		k, v := s.Text()

		if test.key != k {
			t.Errorf("#%d: key: expected %q, got %q\n", n, test.key, k)
		}
		if test.value != v {
			t.Errorf("#%d: value: expected %q, got %q\n", n, test.value, v)
		}
		if err := s.Err(); err != nil {
			t.Errorf("#%d: %v", n, err)
		}

		if s.separator != nil && len(_DEF_SEPARATOR) == len(s.separator) {
			if _DEF_SEPARATOR[0] != s.separator[0] {
				t.Errorf("#%d: separator: expected %q, got %q\n", n, _DEF_SEPARATOR, s.separator)
			}
		}
	}
}

var errorTests = []struct {
	in  string
	err error
}{
	{"FOO=bar z", extraCharError(1)},

	{" =bar", keyError(1)},
	{"FOO", valueError(1)},
	{" FOO=", valueError(1)},

	{"FOO_€=bar", noASCIIKeyError(1)},

	{`FOO="bar`, openQuoteError(1)},
	{`FOO='bar`, openQuoteError(1)},
}

func TestErrors(t *testing.T) {
	var err error
	for n, test := range errorTests {
		s := NewScanner(bytes.NewBufferString(test.in))
		s.Scan()
		err = s.Err()

		if test.err != err {
			t.Errorf("#%d: expected error %q, got %v\n", n, test.err, err)
		}
	}
}
