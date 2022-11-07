// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

// Copied from https://github.com/tinygo-org/tinygo/blob/3dbc4d52105f4209ece1332f0272f293745ac0bf/src/runtime/gc_conservative.go
// with modifications to use malloc for underlying memory storage.

package agc

// This memory manager is a textbook mark/sweep implementation, heavily inspired
// by the MicroPython garbage collector.
//
// The memory manager internally uses blocks of 4 pointers big (see
// bytesPerBlock). Every allocation first rounds up to this size to align every
// block. It will first try to find a chain of blocks that is big enough to
// satisfy the allocation. If it finds one, it marks the first one as the "head"
// and the following ones (if any) as the "tail" (see below). If it cannot find
// any free space, it will perform a garbage collection cycle and try again. If
// it still cannot find any free space, it gives up.
//
// Every block has some metadata, which is stored at the end of the heap.
// The four states are "free", "head", "tail", and "mark". During normal
// operation, there are no marked blocks. Every allocated object starts with a
// "head" and is followed by "tail" blocks. The reason for this distinction is
// that this way, the start and end of every object can be found easily.
//
// Metadata is stored in a special area at the end of the heap, in the area
// metadataStart..heapEnd. The actual blocks are stored in
// heapStart..metadataStart.
//
// More information:
// https://aykevl.nl/2020/09/gc-tinygo
// https://github.com/micropython/micropython/wiki/Memory-Manager
// https://github.com/micropython/micropython/blob/master/py/gc.c
// "The Garbage Collection Handbook" by Richard Jones, Antony Hosking, Eliot
// Moss.

import (
	"unsafe"
)

//export GC_malloc
func GC_malloc(size uintptr) unsafe.Pointer

//export GC_add_roots
func GC_add_roots(from uintptr, to uintptr)

//export GC_gcollect
func GC_gcollect()

//export GC_get_all_interior_pointers
func GC_get_all_interior_pointers() int32

// Initialize the memory allocator.
// No memory may be allocated before this is called. That means the runtime and
// any packages the runtime depends upon may not allocate memory during package
// initialization.
func init() {
	// GC_add_roots(globalsStart, globalsEnd)
}

// alloc tries to find some free space on the heap, possibly doing a garbage
// collection cycle if needed. If no space is free, it panics.
//
//go:linkname alloc runtime.alloc
func alloc(size uintptr, layout unsafe.Pointer) unsafe.Pointer {
	buf := GC_malloc(size)
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
