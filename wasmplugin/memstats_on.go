// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build memstats

package wasmplugin

import (
	"runtime"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

func logMemStats() {
	ms := runtime.MemStats{}
	runtime.ReadMemStats(&ms)
	proxywasm.LogDebugf(
		"Sys: %d, HeapSys: %d, HeapIdle: %d, HeapReleased: %d, TotalAlloc: %d",
		ms.Sys,
		ms.HeapSys,
		ms.HeapIdle,
		ms.HeapReleased,
		ms.TotalAlloc)
}
