// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package user

import (
	"testing"
	"time"
)

func TestSecToDays(t *testing.T) {
	now := time.Now()

	if now.Day() > 3 {
		before := time.Date(now.Year(), now.Month(), now.Day()-3,
			now.Hour(), now.Minute(), now.Second(), now.Nanosecond(),
			time.Local)

		diff := secToDay(now.Unix()) - secToDay(before.Unix())
		if diff != 3 {
			t.Fatalf("expected to get a difference of 3 days, got %d", diff)
		}
	}
}
