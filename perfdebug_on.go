// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build perfdebug

package main

import (
	"runtime"
	"time"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

func currentTime() time.Time {
	return time.Now()
}

func logTime(msg string, start time.Time) {
	proxywasm.LogDebugf("%s took %s", msg, time.Since(start))
}

func logMemStats() {
	ms := runtime.MemStats{}
	runtime.ReadMemStats(&ms)
	proxywasm.LogDebugf(
		"Sys: %d, HeapSys: %d, HeapIdle: %d, HeapInuse: %d, HeapReleased: %d, TotalAlloc: %d, Mallocs: %d, Frees: %d, Live: %d, GCSys: %d",
		ms.Sys,
		ms.HeapSys,
		ms.HeapIdle,
		ms.HeapInuse,
		ms.HeapReleased,
		ms.TotalAlloc,
		ms.Mallocs,
		ms.Frees,
		ms.Mallocs-ms.Frees,
		ms.GCSys)
}
