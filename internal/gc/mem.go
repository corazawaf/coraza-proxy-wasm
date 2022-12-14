// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package gc

import "unsafe"

//go:linkname memzero runtime.memzero
func memzero(ptr unsafe.Pointer, size uintptr)

//export mi_aligned_alloc
func mi_aligned_alloc(alignment uintptr, size uintptr) unsafe.Pointer

//export mi_zalloc_aligned
func mi_zalloc_aligned(size uintptr, alignment uintptr) unsafe.Pointer

//export mi_malloc
func mi_malloc(size uintptr) unsafe.Pointer

//export mi_calloc
func mi_calloc(count uintptr, size uintptr) unsafe.Pointer

//export mi_free
func mi_free(ptr unsafe.Pointer)

// Not exported by mimalloc on __wasi__ by default so we implement here.

//export __libc_malloc
func __libc_malloc(size uintptr) unsafe.Pointer {
	return mi_malloc(size)
}

//export __libc_calloc
func __libc_calloc(count uintptr, size uintptr) unsafe.Pointer {
	return mi_calloc(count, size)
}

//export __libc_free
func __libc_free(ptr unsafe.Pointer) {
	mi_free(ptr)
}

// Used by mimalloc for delayed free but Envoy doesn't stub it yet.
// We don't use delayed free, so it's fine to stub it out.

//export sched_yield
func sched_yield() int32 {
	return 0
}
