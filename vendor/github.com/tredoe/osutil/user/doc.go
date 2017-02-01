// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/* Package user provides access to UNIX users database in local files.

You must have enough privileges to access to databases in shadowed files
'/etc/shadow' and '/etc/gshadow'. This usually means have to be root.
Note: those files are backed-up before of be modified.

In testing, to print the configuration read from the system, there is to use
"-v" flag.
*/
package user
