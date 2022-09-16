// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package injection

import (
	"reflect"
	"runtime"
	"unsafe"
)

//export libinjection_sqli
func isSQLi(sPtr unsafe.Pointer, sLen uint32, fpPtr unsafe.Pointer) uint32

//export libinjection_xss
func isXSS(sPtr unsafe.Pointer, sLen uint32) uint32

func IsSQLi(s string) (bool, string) {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	fp := "00000000"
	fpSh := (*reflect.StringHeader)(unsafe.Pointer(&fp))
	res := isSQLi(unsafe.Pointer(sh.Data), uint32(sh.Len), unsafe.Pointer(fpSh.Data))
	runtime.KeepAlive(s)

	return res == 1, fp
}

func IsXSS(s string) bool {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	res := isXSS(unsafe.Pointer(sh.Data), uint32(sh.Len))
	runtime.KeepAlive(s)

	return res == 1
}
