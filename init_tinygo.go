// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package main

import _ "github.com/corazawaf/coraza-proxy-wasm/internal/gc"

// #cgo LDFLAGS: lib/libinjection.a lib/libmimalloc.a lib/libgc.a
import "C"
