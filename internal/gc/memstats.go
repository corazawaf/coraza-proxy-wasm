// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package gc

//export GC_get_gc_no
func GC_get_gc_no() uint32

//export GC_get_heap_usage_safe
func GC_get_heap_usage_safe(pHeapSize *uint32, pFreeBytes *uint32, pUnmappedBytes *uint32, pBytesSinceGC *uint32, pTotalBytes *uint32)

//export GC_get_obtained_from_os_bytes
func GC_get_obtained_from_os_bytes() uint32

//export mi_process_info
func mi_process_info(elapsedMS *uint32, userMS *uint32, systemMS *uint32, currentRSS *uint32, peakRSS *uint32, currentCommit *uint32, peakCommit *uint32, pageFaults *uint32)

// MemStats is like runtime.MemStats but contains a few more fields relevant to our allocators
// and avoids a dependency on the runtime package.
type MemStats struct {
	Sys          uint32
	HeapSys      uint32
	HeapAlloc    uint32
	HeapIdle     uint32
	HeapReleased uint32
	TotalAlloc   uint32
	NumGC        uint32

	// The following fields are not part of runtime.MemStats.

	BytesSinceGC uint32
}

func ReadMemStats(ms *MemStats) {
	var heapSize, freeBytes, unmappedBytes, bytesSinceGC, totalBytes uint32
	GC_get_heap_usage_safe(&heapSize, &freeBytes, &unmappedBytes, &bytesSinceGC, &totalBytes)

	var peakRSS uint32
	mi_process_info(nil, nil, nil, nil, &peakRSS, nil, nil, nil)

	gcOSBytes := GC_get_obtained_from_os_bytes()

	// Since the GC delegates to malloc/free for underlying pages, the total memory occupied by both C malloc/free and
	// the GC is malloc's peak RSS itself. Because mimalloc does not return pages when run under wasm, peak/current RSS
	// and commit are all the same value and we only record one.
	ms.Sys = peakRSS
	ms.HeapSys = gcOSBytes
	ms.HeapAlloc = heapSize
	ms.HeapIdle = freeBytes
	ms.HeapReleased = unmappedBytes
	ms.TotalAlloc = totalBytes
	ms.NumGC = GC_get_gc_no()
	ms.BytesSinceGC = bytesSinceGC
}
