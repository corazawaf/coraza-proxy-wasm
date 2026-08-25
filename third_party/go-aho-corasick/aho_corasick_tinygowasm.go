//go:build tinygo.wasm || aho_corasick_cgo

package aho_corasick

/*

#include <stddef.h>

void* new_matcher(void* patterns, void* lens, int num_patterns, int ascii_case_insensitive, int dfa, int match_kind);
void delete_matcher(void* matcher);
void* find_iter(void* ac, void* value, int value_len);
int find_iter_next(void* iter, size_t* patternOut, size_t* startOut, size_t* endOut);
void find_iter_delete(void* iter);

void* overlapping_iter(void* ac, void* value, int value_len);
int overlapping_iter_next(void* iter, size_t* patternOut, size_t* startOut, size_t* endOut);
void overlapping_iter_delete(void* iter);

void* matches(void* ac, void* value, size_t value_len, size_t limit, size_t* numOut);
void matches_delete(void* matches, size_t num);
*/
import "C"

import (
	"reflect"
	"runtime"
	"unsafe"
)

type ahoCorasickABI struct{}

func newABI() *ahoCorasickABI {
	return &ahoCorasickABI{}
}

func (abi *ahoCorasickABI) startOperation(memorySize int) {
}

func (abi *ahoCorasickABI) endOperation() {
}

func (abi *ahoCorasickABI) newMatcher(patterns []string, patternBytes int, asciiCaseInsensitive bool, dfa bool, matchKind int) uintptr {
	patternsBuf := make([]byte, patternBytes)
	lens := make([]uintptr, len(patterns))

	off := 0
	for i, p := range patterns {
		copy(patternsBuf[off:], p)
		off += len(p)
		lens[i] = uintptr(len(p))
	}

	patternsSh := (*reflect.SliceHeader)(unsafe.Pointer(&patternsBuf))
	lensSh := (*reflect.SliceHeader)(unsafe.Pointer(&lens))
	aci := 0
	if asciiCaseInsensitive {
		aci = 1
	}

	d := 0
	if dfa {
		d = 1
	}
	ptr := C.new_matcher(unsafe.Pointer(patternsSh.Data), unsafe.Pointer(lensSh.Data), C.int(len(patterns)), C.int(aci), C.int(d), C.int(matchKind))
	runtime.KeepAlive(patterns)
	return uintptr(ptr)
}

func (abi *ahoCorasickABI) deleteMatcher(ptr uintptr) {
	C.delete_matcher(unsafe.Pointer(ptr))
}

func (abi *ahoCorasickABI) findIter(acPtr uintptr, value cString) uintptr {
	ptr := C.find_iter(unsafe.Pointer(acPtr), unsafe.Pointer(value.ptr), C.int(value.length))
	return uintptr(ptr)
}

func (abi *ahoCorasickABI) findIterNext(iterPtr uintptr) (pattern int, start int, end int, ok bool) {
	var patternC, startC, endC C.size_t
	okC := C.find_iter_next(unsafe.Pointer(iterPtr), &patternC, &startC, &endC)
	if okC > 0 {
		ok = true
	}
	return int(patternC), int(startC), int(endC), ok
}

func (abi *ahoCorasickABI) findIterDelete(iterPtr uintptr) {
	C.find_iter_delete(unsafe.Pointer(iterPtr))
}

func (abi *ahoCorasickABI) overlappingIter(acPtr uintptr, value cString) uintptr {
	ptr := C.overlapping_iter(unsafe.Pointer(acPtr), unsafe.Pointer(value.ptr), C.int(value.length))
	return uintptr(ptr)
}

func (abi *ahoCorasickABI) overlappingIterNext(iterPtr uintptr) (pattern int, start int, end int, ok bool) {
	var patternC, startC, endC C.size_t
	okC := C.overlapping_iter_next(unsafe.Pointer(iterPtr), &patternC, &startC, &endC)
	if okC > 0 {
		ok = true
	}
	return int(patternC), int(startC), int(endC), ok
}

func (abi *ahoCorasickABI) overlappingIterDelete(iterPtr uintptr) {
	C.overlapping_iter_delete(unsafe.Pointer(iterPtr))
}

func (abi ahoCorasickABI) findN(iter uintptr, valueStr string, value cString, n int, matchWholeWords bool) []Match {
	var resLen C.size_t
	matchesPtr := C.matches(unsafe.Pointer(iter), unsafe.Pointer(value.ptr), C.size_t(value.length), C.size_t(n), &resLen)
	defer C.matches_delete(matchesPtr, resLen)

	res := unsafe.Slice((*uintptr)(unsafe.Pointer(matchesPtr)), resLen)

	num := int(resLen) / 3
	matches := make([]Match, 0, num)
	for i := 0; i < num; i++ {
		start := int(res[i*3+1])
		end := int(res[i*3+2])
		if matchWholeWords && isNotWholeWord(valueStr, start, end) {
			continue
		}
		var m Match
		m.pattern = int(res[i*3])
		m.start = start
		m.end = end
		matches = append(matches, m)
	}

	return matches
}

type cString struct {
	ptr    uintptr
	length int
}

func (abi *ahoCorasickABI) newCString(s string) cString {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return cString{
		ptr:    sh.Data,
		length: int(sh.Len),
	}
}

func (abi *ahoCorasickABI) newOwnedCString(s string) cString {
	return abi.newCString(s)
}

func (abi *ahoCorasickABI) freeOwnedCStringPtr(ptr uintptr) {
}
