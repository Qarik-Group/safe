// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package file

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// Contain returns whether the named file contains the byte slice b. The
// return value is a boolean.
func Contain(filename string, b []byte) (bool, error) {
	f, err := os.Open(filename)
	if err != nil {
		return false, fmt.Errorf("Contain: %s", err)
	}
	defer f.Close()

	buf := bufio.NewReader(f)

	for {
		line, err := buf.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if bytes.Contains(line, b) {
			return true, nil
		}
	}
	return false, nil
}

// ContainString returns whether the named file contains the string s. The
// return value is a boolean.
func ContainString(filename, s string) (bool, error) {
	f, err := os.Open(filename)
	if err != nil {
		return false, fmt.Errorf("ContainString: %s", err)
	}
	defer f.Close()

	buf := bufio.NewReader(f)

	for {
		line, err := buf.ReadString('\n')
		if err == io.EOF {
			break
		}
		if strings.Contains(line, s) {
			return true, nil
		}
	}
	return false, nil
}
