// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sh

import (
	"errors"
	"testing"
)

var testsOk = []struct {
	cmd   string
	match bool
}{
	// expansion of "~"
	{"ls ~/", true},
}

var testsOutput = []struct {
	cmd   string
	out   string
	match bool
}{
	// values in match
	{"true", "", true},
	{"false", "", false},
	{`grep foo not_exist.go`, "", false},         // no found
	{`grep package sh.go`, "package sh\n", true}, // found

	// pipes
	{"ls sh*.go | wc -l", "2\n", true},

	// quotes
	{`sh -c 'echo 123'`, "123\n", true},
	{`sh -c "echo 123"`, "123\n", true},
	{`find -name 'sh*.go'`, "./sh.go\n./sh_test.go\n", true},
}

var testsError = []struct {
	cmd string
	err error // from Stderr
}{
	{"| ls ", errNoCmdInPipe},
	{"| ls | wc", errNoCmdInPipe},
	{"ls|", errNoCmdInPipe},
	{"ls| wc|", errNoCmdInPipe},
	{"ls| |wc", errNoCmdInPipe},

	{"LANG= C find", errEnvVar},
	{"LANG =C find", errEnvVar},

	{`LANG=C find -nop README.md`, errors.New("find: unknown predicate `-nop'")},
}

func TestRun(t *testing.T) {
	for _, v := range testsOk {
		out, match, _ := RunWithMatch(v.cmd)

		if v.match != match {
			t.Errorf("`%s` (match): expected %t, found %t\n", v.cmd, v.match, match)
		}

		if string(out) == "" {
			t.Errorf("`%s`: output is empty", v.cmd)
		}
	}

	for _, v := range testsOutput {
		out, match, _ := RunWithMatch(v.cmd)

		if string(out) != v.out {
			t.Errorf("`%s` (output): expected %q, found %q\n", v.cmd, v.out, out)
		}
		if match != v.match {
			t.Errorf("`%s` (match): expected %t, found %t\n", v.cmd, v.match, match)
		}
	}

	for _, v := range testsError {
		_, err := Run(v.cmd)
		mainErr := err.(runError).err

		if mainErr.Error() != v.err.Error() {
			t.Errorf("`%s` (error): expected %q, found %q\n", v.cmd, v.err, mainErr)
		}
	}
}
