// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package gc

import "unsafe"

//go:linkname memzero runtime.memzero
func memzero(ptr unsafe.Pointer, size uintptr)
