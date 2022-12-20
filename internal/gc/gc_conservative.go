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

void onCollectionEvent();
*/
import "C"

//export GC_set_on_collection_event
func GC_set_on_collection_event(f unsafe.Pointer)

const (
	gcEventStart = 0
)

//export onCollectionEvent
func onCollectionEvent(eventType uint32) {
	switch eventType {
	case gcEventStart:
		markStack()
	}
}

// Initialize the memory allocator.
//
//go:linkname initHeap runtime.initHeap
func initHeap() {
	GC_set_on_collection_event(C.onCollectionEvent)
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

//go:linkname markRoots runtime.markRoots
func markRoots(start, end uintptr) {
	// Roots are already registered in bdwgc so we have nothing to do here.
}

//go:linkname markStack runtime.markStack
func markStack()

// GC performs a garbage collection cycle.
//
//go:linkname GC runtime.GC
func GC() {
	C.GC_gcollect()
}
