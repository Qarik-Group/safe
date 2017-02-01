// Copyright 2010 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"fmt"
	"strings"
	"sync"

	"github.com/tredoe/goutil/cmdutil"
	"github.com/tredoe/goutil/reflectutil"
	"github.com/tredoe/osutil/config/shconf"
	"github.com/tredoe/osutil/user/crypt"
)

// TODO: handle des, bcrypt and rounds in SHA2.

// TODO: Idea: store struct "configData" to run configData.Init() only when
// the configuration files have been modified.

// == System configuration files.

const _CONF_LOGIN = "/etc/login.defs"

type conf_login struct {
	PASS_MIN_DAYS int
	PASS_MAX_DAYS int
	PASS_MIN_LEN  int
	PASS_WARN_AGE int

	SYS_UID_MIN int
	SYS_UID_MAX int
	SYS_GID_MIN int
	SYS_GID_MAX int

	UID_MIN int
	UID_MAX int
	GID_MIN int
	GID_MAX int

	ENCRYPT_METHOD       string // upper
	SHA_CRYPT_MIN_ROUNDS int
	SHA_CRYPT_MAX_ROUNDS int
	// or
	CRYPT_PREFIX string // $2a$
	CRYPT_ROUNDS int    // 8
}

const _CONF_USERADD = "/etc/default/useradd"

type conf_useradd struct {
	HOME  string // Default to '/home'
	SHELL string // Default to '/bin/sh'
}

// == Optional files.

// Used in systems derivated from Debian: Ubuntu, Mint.
const _CONF_ADDUSER = "/etc/adduser.conf"

type conf_adduser struct {
	FIRST_SYSTEM_UID int
	LAST_SYSTEM_UID  int
	FIRST_SYSTEM_GID int
	LAST_SYSTEM_GID  int

	FIRST_UID int
	LAST_UID  int
	FIRST_GID int
	LAST_GID  int
}

// Used in Arch, Manjaro, OpenSUSE.
// But it is only used by 'pam_unix2.so'.
const _CONF_PASSWD = "/etc/default/passwd"

// TODO: to see the other options of that file.
type conf_passwd struct {
	CRYPT string // lower
}

// Used in systems derivated from Red Hat: CentOS, Fedora, Mageia, PCLinuxOS.
const _CONF_LIBUSER = "/etc/libuser.conf"

type conf_libuser struct {
	login_defs  string
	crypt_style string // lower

	// For SHA2
	hash_rounds_min int
	hash_rounds_max int
}

// * * *

var _DEBUG bool

// A configData represents the configuration used to add users and groups.
type configData struct {
	login   conf_login
	useradd conf_useradd

	crypter crypt.Crypter
	sync.Once
}

var config configData

// init sets the configuration data.
func (c *configData) init() error {
	_conf_login := &conf_login{}
	cmdutil.SetPrefix("\n* ", "")

	cfg, err := shconf.ParseFile(_CONF_LOGIN)
	if err != nil {
		return err
	} else {
		if err = cfg.Unmarshal(_conf_login); err != nil {
			return err
		}
		if _DEBUG {
			cmdutil.Println(_CONF_LOGIN)
			reflectutil.PrintStruct(_conf_login)
		}

		if _conf_login.PASS_MAX_DAYS == 0 {
			_conf_login.PASS_MAX_DAYS = 99999
		}
		if _conf_login.PASS_WARN_AGE == 0 {
			_conf_login.PASS_WARN_AGE = 7
		}
	}

	cfg, err = shconf.ParseFile(_CONF_USERADD)
	if err != nil {
		return err
	} else {
		_conf_useradd := &conf_useradd{}
		if err = cfg.Unmarshal(_conf_useradd); err != nil {
			return err
		}
		if _DEBUG {
			cmdutil.Println(_CONF_USERADD)
			reflectutil.PrintStruct(_conf_useradd)
		}

		if _conf_useradd.HOME == "" {
			_conf_useradd.HOME = "/home"
		}
		if _conf_useradd.SHELL == "" {
			_conf_useradd.SHELL = "/bin/sh"
		}
		config.useradd = *_conf_useradd
	}

	// Optional files

	found, err := exist(_CONF_ADDUSER) // Based in Debian.
	if found {
		cfg, err := shconf.ParseFile(_CONF_ADDUSER)
		if err != nil {
			return err
		}
		_conf_adduser := &conf_adduser{}
		if err = cfg.Unmarshal(_conf_adduser); err != nil {
			return err
		}
		if _DEBUG {
			cmdutil.Println(_CONF_ADDUSER)
			reflectutil.PrintStruct(_conf_adduser)
		}

		if _conf_login.SYS_UID_MIN == 0 || _conf_login.SYS_UID_MAX == 0 ||
			_conf_login.SYS_GID_MIN == 0 || _conf_login.SYS_GID_MAX == 0 ||
			_conf_login.UID_MIN == 0 || _conf_login.UID_MAX == 0 ||
			_conf_login.GID_MIN == 0 || _conf_login.GID_MAX == 0 {

			_conf_login.SYS_UID_MIN = _conf_adduser.FIRST_SYSTEM_UID
			_conf_login.SYS_UID_MAX = _conf_adduser.LAST_SYSTEM_UID
			_conf_login.SYS_GID_MIN = _conf_adduser.FIRST_SYSTEM_GID
			_conf_login.SYS_GID_MAX = _conf_adduser.LAST_SYSTEM_GID

			_conf_login.UID_MIN = _conf_adduser.FIRST_UID
			_conf_login.UID_MAX = _conf_adduser.LAST_UID
			_conf_login.GID_MIN = _conf_adduser.FIRST_GID
			_conf_login.GID_MAX = _conf_adduser.LAST_GID
		}
	} else if err != nil {
		return err

	} else if found, err = exist(_CONF_LIBUSER); found { // Based in Red Hat.
		cfg, err := shconf.ParseFile(_CONF_LIBUSER)
		if err != nil {
			return err
		}
		_conf_libuser := &conf_libuser{}
		if err = cfg.Unmarshal(_conf_libuser); err != nil {
			return err
		}
		if _DEBUG {
			cmdutil.Println(_CONF_LIBUSER)
			reflectutil.PrintStruct(_conf_libuser)
		}

		if _conf_libuser.login_defs != _CONF_LOGIN {
			_conf_login.ENCRYPT_METHOD = _conf_libuser.crypt_style
			_conf_login.SHA_CRYPT_MIN_ROUNDS = _conf_libuser.hash_rounds_min
			_conf_login.SHA_CRYPT_MAX_ROUNDS = _conf_libuser.hash_rounds_max
		}
	} else if err != nil {
		return err

	} /*else if found, err = exist(_CONF_PASSWD); found {
		cfg, err := shconf.ParseFile(_CONF_PASSWD)
		if err != nil {
			return err
		}
		_conf_passwd := &conf_passwd{}
		if err = cfg.Unmarshal(_conf_passwd); err != nil {
			return err
		}
		if _DEBUG {
			cmdutil.Println(_CONF_PASSWD)
			reflectutil.PrintStruct(_conf_passwd)
		}

		if _conf_passwd.CRYPT != "" {
			_conf_login.ENCRYPT_METHOD = _conf_passwd.CRYPT
		}
	} else if err != nil {
		return err
	}*/

	switch strings.ToUpper(_conf_login.ENCRYPT_METHOD) {
	case "MD5":
		c.crypter = crypt.New(crypt.MD5)
	case "SHA256":
		c.crypter = crypt.New(crypt.SHA256)
	case "SHA512":
		c.crypter = crypt.New(crypt.SHA512)
	case "":
		if c.crypter, err = lookupCrypter(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("user: requested cryp function is unavailable: %s",
			c.login.ENCRYPT_METHOD)
	}

	if _conf_login.SYS_UID_MIN == 0 || _conf_login.SYS_UID_MAX == 0 ||
		_conf_login.SYS_GID_MIN == 0 || _conf_login.SYS_GID_MAX == 0 ||
		_conf_login.UID_MIN == 0 || _conf_login.UID_MAX == 0 ||
		_conf_login.GID_MIN == 0 || _conf_login.GID_MAX == 0 {

		_conf_login.SYS_UID_MIN = 100
		_conf_login.SYS_UID_MAX = 999
		_conf_login.SYS_GID_MIN = 100
		_conf_login.SYS_GID_MAX = 999

		_conf_login.UID_MIN = 1000
		_conf_login.UID_MAX = 29999
		_conf_login.GID_MIN = 1000
		_conf_login.GID_MAX = 29999
	}

	config.login = *_conf_login
	return nil
}

// loadConfig loads user configuration.
// It has to be loaded before of edit some file.
func loadConfig() {
	config.Do(func() {
		//checkRoot()
		if err := config.init(); err != nil {
			panic(err)
		}
	})
}
