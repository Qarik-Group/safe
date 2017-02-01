// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import (
	"os"
	"testing"

	"github.com/tredoe/osutil/sh"
)

func TestCreate(t *testing.T) {
	if err := CreateString(TEMP_FILE, `
Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor 
incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis 
nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. 
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu 
fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in 
culpa qui officia deserunt mollit anim id est laborum.
`); err != nil {
		t.Fatal(err)
	}

	out, err := sh.Runf("wc -l %s", TEMP_FILE)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != '7' {
		t.Fatalf("got %q lines, want 7", out[0])
	}
}

func TestEdit(t *testing.T) {
	line := "I've heard that the night is all magic.\n"

	e, err := NewEdit(TEMP_FILE)
	if err != nil {
		t.Fatal(err)
	}
	/*defer func() {
		if err = os.Remove(TEMP_FILE); err != nil {
			t.Error(err)
		}
	}()*/
	defer func() {
		if err = e.Close(); err != nil {
			t.Error(err)
		}
	}()

	// The backup should be created.
	if _, err = os.Stat(TEMP_BACKUP); err != nil {
		t.Error(err)
	}
	defer func() {
		if err = os.Remove(TEMP_BACKUP); err != nil {
			t.Error(err)
		}
	}()

	// Append
	if err = e.AppendString("\n" + line); err != nil {
		t.Error(err)
	} else {
		if out, _ := sh.Run("tail -n1 " + TEMP_FILE); string(out) != line {
			t.Errorf("Append => got %q, want %q", out, line)
		}
	}

	/*// Insert
	if err = e.InsertString(line); err != nil {
		t.Error(err)
	} else {
		if out, _, _ := sh.Run("head -n1 " + TEMP_FILE); out != line {
			t.Errorf("Insert => got %q, want %q", out, line)
		}
	}*/

	// Replace
	repl := []Replacer{
		{"dolor", "DOL_"},
		{"labor", "LABOR_"},
	}
	resul := "3\n"

	if err = e.Replace(repl); err != nil {
		t.Error(err)
	} else {
		if out, _ := sh.Runf("grep -c %s %s", repl[1].Replace, TEMP_FILE); string(out) != resul {
			t.Errorf("Replace (%s) => got %v, want %v", repl[1].Replace, out, resul)
		}
	}

	repl = []Replacer{
		{"DOL_", "dOlOr"},
		{"LABOR_", "lAbOr"},
	}
	resul = "1\n"

	if err = e.ReplaceN(repl, 1); err != nil {
		t.Error(err)
	} else {
		for i := 0; i <= 1; i++ {
			if out, _ := sh.Runf("grep -c %s %s", repl[i].Replace, TEMP_FILE); string(out) != resul {
				t.Errorf("Replace (%s) => got %v, want %v", repl[i].Replace, out, resul)
			}
		}
	}

	// ReplaceAtLine
	replAt := []ReplacerAtLine{
		{"LABOR", "o", "OO"},
	}
	resul = "2\n"

	if err = e.ReplaceAtLine(replAt); err != nil {
		t.Error(err)
	} else {
		if out, _ := sh.Run("grep -c OO " + TEMP_FILE); string(out) != resul {
			t.Errorf("ReplaceAtLine => got %v, want %v", out, resul)
		}
	}

	replAt = []ReplacerAtLine{
		{"heard", "a", "AA"},
	}
	resul = "1\n"

	if err = e.ReplaceAtLineN(replAt, 2); err != nil {
		t.Error(err)
	} else {
		if out, _ := sh.Runf("tail -n1 %s | grep -c A", TEMP_FILE); string(out) != resul {
			t.Errorf("ReplaceAtLineN => got %v, want %v", out, resul)
		}
	}

	// Comment
	resul = "2\n"

	if err = e.Comment([]string{"night", "quis"}); err != nil {
		t.Error(err)
	} else {
		if out, _ := sh.Runf("grep -c %s %s", e.CommentChar, TEMP_FILE); string(out) != resul {
			t.Errorf("Comment => got %v, want %v", out, resul)
		}
	}

	// CommentOut
	resul = "0\n"

	if err = e.CommentOut([]string{"night", "quis"}); err != nil {
		t.Error(err)
	} else {
		if out, _ := sh.Runf("grep -c %s %s", e.CommentChar, TEMP_FILE); string(out) != resul {
			t.Errorf("CommentOut => got %v, want %v", out, resul)
		}
	}
}
