// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/* Package file handles common operations in files.

The editing of files is very important in the shell scripting to working with
the configuration files. There are a great number of functions related to it,
avoiding to have to use an external command to get the same result and with the
advantage of that it creates automatically a backup before of editing.

NewEdit creates a new struct, edit, which has a variable, CommentChar,
with a value by default, '#'. That value is the character used in comments.
*/
package file
