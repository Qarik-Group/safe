// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Passwords
//
// If the passwd field contains some string that is not a valid result of
// hashing, for instance "!" or "*", the user will not be able to use a unix
// passwd to log in (but the user may log in the system by other means).
//
// A passwd field which starts with a exclamation mark means that the passwd is
// locked. The remaining characters on the line represent the passwd field before
// the passwd was locked.

package user

import (
	"bufio"
	"errors"
	"io"
	"log"
	"os"

	"github.com/tredoe/osutil/user/crypt"
	_ "github.com/tredoe/osutil/user/crypt/md5_crypt"
	_ "github.com/tredoe/osutil/user/crypt/sha256_crypt"
	_ "github.com/tredoe/osutil/user/crypt/sha512_crypt"
	//_ "github.com/tredoe/osutil/user/crypt/bcrypt"
)

const _LOCK_CHAR = '!' // Character added at the beginning of the passwd to lock it.

var ErrShadowPasswd = errors.New("no found user with shadowed passwd")

// lookupCrypter returns the first crypt function found in shadowed passwd file.
func lookupCrypter() (crypt.Crypter, error) {
	f, err := os.Open(_SHADOW_FILE)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := bufio.NewReader(f)

	for {
		line, _, err := buf.ReadLine()
		if err != nil {
			if err == io.EOF {
				return nil, ErrShadowPasswd
			}
			log.Print(err)
			continue
		}

		shadow, err := parseShadow(string(line))
		if err != nil {
			log.Print(err)
			continue
		}
		if shadow.password[0] == '$' {
			return crypt.NewFromHash(shadow.password), nil
		}
	}
	return nil, ErrShadowPasswd
}

// SetCrypter sets the crypt function to can hash the passwords.
// The type "crypt.Crypt" comes from package "github.com/tredoe/osutil/user/crypt".
func SetCrypter(c crypt.Crypt) {
	loadConfig()
	config.crypter = crypt.New(c)
}

// Passwd sets a hashed passwd for the actual user.
// The passwd must be supplied in clear-text.
func (s *Shadow) Passwd(key []byte) {
	loadConfig()
	s.password, _ = config.crypter.Generate(key, nil)
	s.setChange()
}

// Passwd sets a hashed passwd for the actual group.
// The passwd must be supplied in clear-text.
func (gs *GShadow) Passwd(key []byte) {
	loadConfig()
	gs.password, _ = config.crypter.Generate(key, nil)
}

// == Change passwd

// ChPasswd updates passwd.
// The passwd must be supplied in clear-text.
func ChPasswd(user string, key []byte) error {
	shadow, err := LookupShadow(user)
	if err != nil {
		return err
	}
	shadow.Passwd(key)

	return edit(user, shadow)
}

// ChGPasswd updates group passwd.
// The passwd must be supplied in clear-text.
func ChGPasswd(group string, key []byte) error {
	gshadow, err := LookupGShadow(group)
	if err != nil {
		return err
	}
	gshadow.Passwd(key)

	return edit(group, gshadow)
}

// == Locking

// LockUser locks the passwd of the given user.
func LockUser(name string) error {
	shadow, err := LookupShadow(name)
	if err != nil {
		return err
	}

	if shadow.password[0] != _LOCK_CHAR {
		shadow.password = string(_LOCK_CHAR) + shadow.password
		return edit(name, shadow)
	}
	return nil
}

// UnlockUser unlocks the passwd of the given user.
func UnlockUser(name string) error {
	shadow, err := LookupShadow(name)
	if err != nil {
		return err
	}

	if shadow.password[0] == _LOCK_CHAR {
		shadow.password = shadow.password[1:]
		return edit(name, shadow)
	}
	return nil
}
