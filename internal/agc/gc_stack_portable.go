// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package agc

import (
	"unsafe"
)

//go:extern runtime.stackChainStart
var stackChainStart *stackChainObject

type stackChainObject struct {
	parent   *stackChainObject
	numSlots uintptr
}

func addStackRoots() {
	stackObject := stackChainStart
	for stackObject != nil {
		start := uintptr(unsafe.Pointer(stackObject)) + unsafe.Sizeof(uintptr(0))*2
		end := start + stackObject.numSlots*unsafe.Alignof(uintptr(0))
		GC_add_roots(start, end)
		stackObject = stackObject.parent
	}
}
