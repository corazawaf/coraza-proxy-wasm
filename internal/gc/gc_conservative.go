// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package gc

import (
	"unsafe"
)

/*
void* GC_malloc(unsigned int size);
void GC_free(void* ptr);
void GC_gcollect();
*/
import "C"

// Initialize the memory allocator. We currently do not have anything needing initialization.
//
//go:linkname initHeap runtime.initHeap
func initHeap() {
}

// alloc tries to find some free space on the heap, possibly doing a garbage
// collection cycle if needed. If no space is free, it panics.
//
//go:linkname alloc runtime.alloc
func alloc(size uintptr, layout unsafe.Pointer) unsafe.Pointer {
	buf := C.GC_malloc(C.uint(size))
	if buf == nil {
		panic("out of memory")
	}
	memzero(buf, size)
	return buf
}

//go:linkname free runtime.free
func free(ptr unsafe.Pointer) {
	C.GC_free(ptr)
}

// GC performs a garbage collection cycle.
//
//go:linkname GC runtime.GC
func GC() {
	C.GC_gcollect()
}

//go:linkname KeepAlive runtime.KeepAlive
func KeepAlive(x interface{}) {
	// Unimplemented for now.
}

//go:linkname SetFinalizer runtime.SetFinalizer
func SetFinalizer(obj interface{}, finalizer interface{}) {
	// Unimplemented for now.
}
