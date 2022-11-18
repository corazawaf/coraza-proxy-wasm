// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package gc

import (
	"runtime/volatile"
	"unsafe"
)

//export GC_malloc
func GC_malloc(size uintptr) unsafe.Pointer

//export GC_gcollect
func GC_gcollect()

// Initialize the memory allocator. Actually all we are doing here is forcing the compiler
// to mark stackChainStart as volatile.
func init() {
	// GC_set_on_collection_event(C.onCollectionEvent)
	// Hack to force LLVM to consider stackChainStart to be live.
	// Without this hack, loads and stores may be considered dead and objects on
	// the stack might not be correctly tracked. With this volatile load, LLVM
	// is forced to consider stackChainStart (and everything it points to) as
	// live.
	volatile.LoadUint32((*uint32)(unsafe.Pointer(&stackChainStart)))
}

// alloc tries to find some free space on the heap, possibly doing a garbage
// collection cycle if needed. If no space is free, it panics.
//
//go:linkname alloc runtime.alloc
func alloc(size uintptr, layout unsafe.Pointer) unsafe.Pointer {
	buf := GC_malloc(size)
	if buf == nil {
		panic("out of memory")
	}
	memzero(buf, size)
	return buf
}

// GC performs a garbage collection cycle.
func GC() {
	GC_gcollect()
}

func KeepAlive(x interface{}) {
	// Unimplemented. Only required with SetFinalizer().
}

func SetFinalizer(obj interface{}, finalizer interface{}) {
	// Unimplemented.
}
