// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build memstats

package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"

	"github.com/corazawaf/coraza-proxy-wasm/internal/gc"
)

func logMemStats() {
	ms := gc.MemStats{}
	gc.ReadMemStats(&ms)
	proxywasm.LogDebugf(
		"Sys: %d, HeapSys: %d, HeapAlloc: %d, HeapIdle: %d, HeapReleased: %d, TotalAlloc: %d, NumGC: %d, BytesSinceGC: %d",
		ms.Sys,
		ms.HeapSys,
		ms.HeapAlloc,
		ms.HeapIdle,
		ms.HeapReleased,
		ms.TotalAlloc,
		ms.NumGC,
		ms.BytesSinceGC)
}
