// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !timing

package main

import (
	"time"
)

func currentTime() time.Time {
	return time.Time{}
}

func logTime(msg string, start time.Time) {
	// no-op without build tag
}
