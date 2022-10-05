// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !timing

package main

import (
	"time"
)

func logTime(string, time.Time) {
	// no-op without build tag
}
