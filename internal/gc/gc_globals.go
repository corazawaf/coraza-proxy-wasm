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

// This file implements markGlobals for all the files that don't have a more
// specific implementation.

// markGlobals marks all globals, which are reachable by definition.
//
// This implementation marks all globals conservatively and assumes it can use
// linker-defined symbols for the start and end of the .data section.
func markGlobals() {
	markRoots(globalsStart, globalsEnd)
}
