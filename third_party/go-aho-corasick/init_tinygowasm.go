//go:build tinygo.wasm

// Copyright The OWASP Coraza contributors
// Modifications Copyright (c) 2026 Tigera, Inc.
// SPDX-License-Identifier: Apache-2.0

package aho_corasick

// TIGERA FORK: upstream declared `#cgo LDFLAGS: -Lwasm -laho_corasick` here to
// link this package's own libaho_corasick.a. That archive is gone. The
// aho-corasick C ABI (new_matcher / find_iter / matches / ...) is now compiled
// into the cre2 Rust crate (../go-re2/buildtools/cre2, src/ahocorasick.rs) and
// resolves from libcre2.a at the final wasm link -- go-re2's cgo LDFLAGS
// (-Linternal/wasm -lcre2) put that archive on the shared link line, and
// wasm-ld resolves archive members globally across the whole link.
//
// Two separate Rust staticlibs would collide on std's panic symbols
// (rust_eh_personality, std::panicking::EMPTY_PANIC), which TinyGo 0.39's
// wasm-ld cannot resolve (no --allow-multiple-definition). See TIGERA-FORK.md.
