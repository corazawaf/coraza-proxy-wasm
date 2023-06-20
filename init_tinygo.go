// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package main

import (
	_ "github.com/wasilibs/nottinygc"
	"unsafe"
)

// Some host functions that are not implemented by Envoy end up getting imported anyways
// by code that gets compiled but not executed at runtime. Because we know they are not
// executed, we can stub them out to allow functioning on Envoy. Note, these match the
// names and signatures of libc, not WASI ABI.

//export sched_yield
func sched_yield() int32 {
	return 0
}

//export fdopendir
func fdopendir(fd int32) unsafe.Pointer {
	return nil
}

//export readdir
func readdir(unsafe.Pointer) unsafe.Pointer {
	return nil
}
