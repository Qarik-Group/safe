// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sh

import (
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
)

const PATH = "/sbin:/bin:/usr/sbin:/usr/bin"

const _LOG_FILE = "/.shutil.log" // in boot

var (
	_ENV  []string
	_HOME string // to expand symbol "~"
	BOOT  bool   // does the script is being run during boot?
	DEBUG bool

	logFile *os.File
	Log     = log.New(ioutil.Discard, "", 0)
)

// Sets environment variables and a null logger.
func init() {
	log.SetFlags(0)
	log.SetPrefix("ERROR: ")

	if BOOT {
		_ENV = []string{"PATH=" + PATH} // from file boot
	} else {
		_ENV = os.Environ()
		_HOME = os.Getenv("HOME")
	}

	/*if path := os.Getenv("PATH"); path == "" {
		if err = os.Setenv("PATH", PATH); err != nil {
			log.Print(err)
		}
	}*/
}

// StartLogger initializes the log file.
func StartLogger() {
	var err error

	if BOOT {
		if logFile, err = os.OpenFile(_LOG_FILE, os.O_WRONLY|os.O_TRUNC, 0); err != nil {
			log.Print(err)
		} else {
			Log = log.New(logFile, "", log.Lshortfile)
		}
	} else {
		if Log, err = syslog.NewLogger(syslog.LOG_NOTICE, log.Lshortfile); err != nil {
			log.Fatal(err)
		}
	}
}

// CloseLogger closes the log file.
func CloseLogger() error {
	if BOOT {
		return logFile.Close()
	}
	return nil
}
