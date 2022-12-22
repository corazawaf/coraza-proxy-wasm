// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package gc

import "unsafe"

//go:linkname memzero runtime.memzero
func memzero(ptr unsafe.Pointer, size uintptr)

// Used by mimalloc for delayed free but Envoy doesn't stub it yet.
// We don't use delayed free, so it's fine to stub it out.

//export sched_yield
func sched_yield() int32 {
	return 0
}
