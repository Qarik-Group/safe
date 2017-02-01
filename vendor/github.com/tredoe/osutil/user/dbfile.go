// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

// Since tests will be done in temporary files, there is to use variables to
// change the values at testing.
var (
	_USER_FILE    = "/etc/passwd"
	_GROUP_FILE   = "/etc/group"
	_SHADOW_FILE  = "/etc/shadow"
	_GSHADOW_FILE = "/etc/gshadow"
)
