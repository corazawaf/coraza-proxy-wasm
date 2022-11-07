// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

// Copied from https://github.com/tinygo-org/tinygo/blob/3dbc4d52105f4209ece1332f0272f293745ac0bf/src/runtime/gc_stack_portable.go
// with go:linkname used to override functions in the runtime package.

package agc

import (
	"unsafe"
)

//go:linkname stackChainStart runtime.stackChainStart
var stackChainStart *stackChainObject

type stackChainObject struct {
	parent   *stackChainObject
	numSlots uintptr
}

// trackPointer is a stub function call inserted by the compiler during IR
// construction. Calls to it are later replaced with regular stack bookkeeping
// code.
//
//go:linkname trackPointer runtime.trackPointer
func trackPointer(ptr unsafe.Pointer)

// swapStackChain swaps the stack chain.
// This is called from internal/task when switching goroutines.
//
//go:linkname swapStackChain runtime.swapStackChain
func swapStackChain(dst **stackChainObject) {
	*dst, stackChainStart = stackChainStart, *dst
}
