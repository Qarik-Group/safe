// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package shconf

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

var testdata = []struct {
	k string
	v string
}{
	{"BOOL", "true"},
	{"INT", "-2"},
	{"UINT", "5"},
	{"FLOAT", "3.3"},
	{"STRING", "small"},
}

type conf struct {
	BOOL   bool
	INT    int
	UINT   uint
	FLOAT  float64
	STRING string
}

func TestParseFile(t *testing.T) {
	// == Create temporary file
	file, _ := ioutil.TempFile("", "test")

	buf := bufio.NewWriter(file)
	buf.WriteString("# main comment\n\n")
	buf.WriteString(fmt.Sprintf("%s=%s\n", testdata[0].k, testdata[0].v))
	buf.WriteString(fmt.Sprintf("%s=%s\n\n", testdata[1].k, testdata[1].v))
	buf.WriteString(fmt.Sprintf("%s=%s\n\n", testdata[2].k, testdata[2].v))
	buf.WriteString("# Another comment\n")
	buf.WriteString(fmt.Sprintf("%s=%s\n", testdata[3].k, testdata[3].v))
	buf.WriteString(fmt.Sprintf("%s=%s\n", testdata[4].k, testdata[4].v))
	buf.Flush()
	file.Close()

	defer func() {
		files, err := filepath.Glob(file.Name() + "*")
		if err != nil {
			t.Error(err)
			return
		}
		for _, v := range files {
			if err = os.Remove(v); err != nil {
				t.Error(err)
			}
		}
	}()

	// == Parser
	conf_ok := &conf{}
	conf_bad := conf{}

	cfg, err := ParseFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}

	for k, _ := range cfg.data {
		switch k {
		case "BOOL":
			_, err = cfg.Getbool(k)
		case "INT":
			_, err = cfg.Getint(k)
		case "UINT":
			_, err = cfg.Getuint(k)
		case "FLOAT":
			_, err = cfg.Getfloat(k)
		case "STRING":
			_, err = cfg.Get(k)
		}
		if err != nil {
			t.Errorf("parser: %q got wrong value", k)
		}
	}
	if _, err = cfg.Get("no_key"); err != ErrKey {
		t.Error("expected to get ErrKey")
	}

	if err = cfg.Unmarshal(conf_ok); err != nil {
		t.Error(err)
	}
	if err = cfg.Unmarshal(conf_bad); err != ErrStructPtr {
		t.Error("expected to get ErrStructPtr")
	}

	if _DEF_SEPARATOR[0] != cfg.separator[0] {
		t.Errorf("separator: expected %q, got %q", _DEF_SEPARATOR, cfg.separator)
	}

	// == Editing
	if err = cfg.Set("STRING", "big"); err != nil {
		t.Fatal(err)
	}
	if cfg.data["STRING"] != "big" {
		t.Errorf("edit: value %q could not be set in key %q", "big", "STRING")
	}

	if err = cfg.Set("Not", ""); err == nil {
		t.Errorf("edit: key %q should not exist", "Not")
	}
	// ==

	if testing.Verbose() {
		cfg.Print()
	}
}
