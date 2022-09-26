// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package calloc

import "unsafe"

//export malloc
func libc_malloc(size uintptr) unsafe.Pointer

//export free
func libc_free(ptr unsafe.Pointer)

//export calloc
func libc_calloc(nmemb, size uintptr) unsafe.Pointer

//export __libc_calloc
func __libc_calloc(nmemb, size uintptr) unsafe.Pointer {
	return libc_calloc(nmemb, size)
}

//export __libc_malloc
func __libc_malloc(size uintptr) unsafe.Pointer {
	return libc_malloc(size)
}

//export __libc_free
func __libc_free(ptr unsafe.Pointer) {
	libc_free(ptr)
}

//export posix_memalign
func posix_memalign(memptr *unsafe.Pointer, alignment, size uintptr) int {
	// Ignore alignment for now
	*memptr = libc_malloc(size)
	return 0
}

//export aligned_alloc
func aligned_alloc(alignment, size uintptr) unsafe.Pointer {
	// Ignore alignment for now
	return libc_malloc(size)
}
