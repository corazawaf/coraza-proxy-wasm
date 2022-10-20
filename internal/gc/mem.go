//go:build tinygo

package gc

import "unsafe"

//go:linkname memzero runtime.memzero
func memzero(ptr unsafe.Pointer, size uintptr)

//go:linkname memcpy runtime.memcpy
func memcpy(dst, src unsafe.Pointer, size uintptr)
