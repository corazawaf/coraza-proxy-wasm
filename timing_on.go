// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build timing

package main

import (
	"time"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

func logTime(msg string, start time.Time) {
	proxywasm.LogDebugf("%s took %s", msg, time.Since(start))
}
