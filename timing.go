// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !timing

package main

import (
	"time"
)

var zeroTime = time.Time{}

func currentTime() time.Time {
	return zeroTime
}

func logTime(string, time.Time) {
	// no-op without build tag
}
