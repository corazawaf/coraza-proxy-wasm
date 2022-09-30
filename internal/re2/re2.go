// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package re2

import (
	"reflect"
	"runtime"
	"unsafe"
)

//export cre2_new
func cre2New(patternPtr unsafe.Pointer, patternLen uint32, flags uint32) unsafe.Pointer

//export cre2_delete
func cre2Delete(rePtr unsafe.Pointer)

//export cre2_match
func cre2Match(rePtr unsafe.Pointer, textPtr unsafe.Pointer, textLen uint32, startPos uint32, endPos uint32,
	anchor uint32, matchArrPtr unsafe.Pointer, nmatch uint32) uint32

//export cre2_match8
func cre2Match8(rePtr unsafe.Pointer, textPtr unsafe.Pointer, textLen uint32, startPos uint32, endPos uint32,
	anchor uint32, matchArrPtr unsafe.Pointer, nmatch uint32) uint32

type RegExp struct {
	ptr unsafe.Pointer
}

func Compile(pattern string) (RegExp, error) {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&pattern))
	rePtr := cre2New(unsafe.Pointer(sh.Data), uint32(sh.Len), 0)
	runtime.KeepAlive(pattern)
	// TODO(anuraaga): Propagate compilation errors from re2.
	return RegExp{ptr: rePtr}, nil
}

func (re RegExp) FindStringSubmatch8(text string, f func(int, string)) bool {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&text))
	// Array of cre2_string_t, which is const char* and int, easiest way to get it is an array of ints.
	var matchArr [16]uint32
	matchArrPtr := unsafe.Pointer(&matchArr[0])
	res := cre2Match8(re.ptr, unsafe.Pointer(sh.Data), uint32(sh.Len), 0, uint32(sh.Len), 0, matchArrPtr, 8)
	if res == 0 {
		return false
	}

	// Pointer math! re2 will return matches which are memory pointers into memory corresponding to text.
	// GC semantics are clearest if we convert them to indexes within text rather than dereference the
	// pointers directly.
	textPtr := uint32(sh.Data)

	for i := 0; i < 8; i++ {
		sPtr := matchArr[2*i]
		if sPtr == 0 {
			break
		}
		sLen := matchArr[2*i+1]

		textIdx := sPtr - textPtr
		f(i, text[textIdx:textIdx+sLen])
	}

	return true
}
