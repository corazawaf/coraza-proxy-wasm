// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

// Copied from https://github.com/tinygo-org/tinygo/blob/3dbc4d52105f4209ece1332f0272f293745ac0bf/src/runtime/gc_globals.go
// with private start symbols redefined.

package gc

import "unsafe"

//go:extern __heap_base
var heapStartSymbol [0]byte

//go:extern __global_base
var globalsStartSymbol [0]byte

var (
	globalsStart = uintptr(unsafe.Pointer(&globalsStartSymbol))
	globalsEnd   = uintptr(unsafe.Pointer(&heapStartSymbol))
)
