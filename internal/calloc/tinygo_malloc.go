//go:build tinygo

package calloc

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"unsafe"
)

//export mi_reserve_os_memory
func mi_reserve_os_memory(size uintptr, commit bool, allowLarge bool)

var allocs = make(map[uintptr][]byte)

//export mi_tinygo_alloc
func mi_tinygo_alloc(size uintptr, alignment uintptr) unsafe.Pointer {
	proxywasm.LogDebugf("mi_tinygo_alloc: %d %d", size, alignment)
	buf := make([]byte, size+alignment+1)
	ptr := uintptr(unsafe.Pointer(&buf[0]))
	ptr += 1
	if ptr < alignment {
		// Looks scary, but since we allocated size+alignment, if ptr is less than
		// the requested alignment, we know that alignment still falls within the
		// allocated buffer.
		ptr = alignment
	} else if misalignment := ptr % alignment; misalignment != 0 {
		ptr += (alignment - misalignment)
	}
	allocs[ptr] = buf
	return unsafe.Pointer(ptr)
}

//export mi_tinygo_free
func mi_tinygo_free(ptr unsafe.Pointer) {
	if ptr == nil {
		return
	}
	if _, ok := allocs[uintptr(ptr)]; ok {
		delete(allocs, uintptr(ptr))
	} else {
		panic("free: invalid pointer")
	}
}

//go:linkname isMallocPointer runtime.isMallocPointer
func isMallocPointer(ptr uintptr) bool {
	for _, alloc := range allocs {
		if uintptr(unsafe.Pointer(&alloc[0])) < ptr && ptr <= uintptr(unsafe.Pointer(&alloc[len(alloc)-1])) {
			return true
		}
	}
	return false
}

func init() {
	mi_reserve_os_memory(128*1024*1024, false, true)
}
