// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package ahocorasick

import (
	"reflect"
	"runtime"
	"unsafe"
)

//export new_matcher
func newMatcher(patternsPtr unsafe.Pointer, patternsLen uint32) uint32

//export matches
func matches(matcherPtr uint32, valuePtr unsafe.Pointer, valueLen uint32, n uint32, matchesPtr unsafe.Pointer) uint32

type Matcher struct {
	ptr uint32
}

func NewMatcher(patternsStr string) Matcher {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&patternsStr))
	ac := newMatcher(unsafe.Pointer(sh.Data), uint32(sh.Len))
	runtime.KeepAlive(patternsStr)
	return Matcher{ptr: ac}
}

func (ac Matcher) Matches(value string, n int) []string {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&value))
	matchOffs := make([]uint32, 2*n)
	matchOffsPtr := unsafe.Pointer(&matchOffs[0])
	numMatches := matches(ac.ptr, unsafe.Pointer(sh.Data), uint32(sh.Len), uint32(n), matchOffsPtr)
	var matches []string
	for i := 0; i < int(numMatches); i++ {
		start := matchOffs[2*i]
		end := matchOffs[2*i+1]
		matches = append(matches, value[start:end])
	}
	return matches
}
