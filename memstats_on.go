// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build memstats

package main

import (
	"runtime"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

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
