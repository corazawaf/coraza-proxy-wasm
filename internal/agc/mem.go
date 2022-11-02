// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package agc

import "unsafe"

//go:linkname memzero runtime.memzero
func memzero(ptr unsafe.Pointer, size uintptr)

//go:linkname memcpy runtime.memcpy
func memcpy(dst, src unsafe.Pointer, size uintptr)
