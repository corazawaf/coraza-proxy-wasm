//go:build tinygo

package agc

import "unsafe"

// Simple implementation of mmap delegating to malloc. wasi-libc defines a similar emulation library, but while
// we wouldn't exercise the code path, its use of pread is incompatible with Envoy.
// https://github.com/WebAssembly/wasi-libc/blob/5d8a1409aa85acf8dbb197e13d33489ad1eac656/libc-bottom-half/mman/mman.c

/*
int errno;
*/
import "C"

//export mi_zalloc_aligned
func mi_zalloc_aligned(size uintptr, alignment uintptr) unsafe.Pointer

//export mi_free
func mi_free(ptr unsafe.Pointer)

//export mmap
func mmap(_ unsafe.Pointer, length uintptr, _ int32, _ int32, _ int32, _ uint64) unsafe.Pointer {
	buf := mi_zalloc_aligned(length, 4096)
	if buf == nil {
		C.errno = 132 /* ENOMEM */
		return unsafe.Add(unsafe.Pointer(0), -1)
	}
	return buf
}

//export munmap
func munmap(addr unsafe.Pointer, _ uintptr) int32 {
	mi_free(addr)
	return 0
}

//export mprotect
func mprotect(addr unsafe.Pointer, length uintptr, prot int32) int32 {
	return 0
}
