// Copyright The OWASP Coraza contributors
// Modifications Copyright (c) 2026 Tigera, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// aho-corasick C ABI, backing coraza's @pm / @pmFromFile operators under TinyGo
// wasm (upstream/internal/operators/pm_tinygo.go, which imports the go-aho-corasick
// Go wrapper). The exported symbols (new_matcher / find_iter / matches / ...) are
// byte-for-byte the ones go-aho-corasick's cgo header declares -- copied verbatim
// from github.com/wasilibs/go-aho-corasick's buildtools/aho-corasick/src/lib.rs so
// the Go side links unchanged.
//
// WHY THIS LIVES IN THE cre2 CRATE (not its own archive):
// @pm's matcher is a Rust staticlib, and @rx's cre2 shim is another. Linking two
// separate Rust staticlibs into one TinyGo wasm module makes wasm-ld hit duplicate
// std panic-runtime symbols (rust_eh_personality, std::panicking::EMPTY_PANIC) --
// each archive carries its own copy of std -- and TinyGo 0.39's wasm-ld (LLVM 19)
// has no --allow-multiple-definition to paper over it. Compiling both shims into
// ONE crate gives one std copy and no clash. `regex` already depends on
// aho-corasick, so no new crate enters the build; we just re-export a C ABI over it.
//
// The go-aho-corasick fork drops its own libaho_corasick.a and lets these symbols
// resolve from libcre2.a at the final wasm link (go-re2's cgo LDFLAGS put -lcre2 on
// the link line). See third_party/go-aho-corasick/TIGERA-FORK.md.

use aho_corasick::{
    AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, FindIter, FindOverlappingIter, MatchKind,
};
use std::slice;
use std::str;

#[no_mangle]
pub extern "C" fn new_matcher(
    patterns_ptr: usize,
    patterns_len: *const usize,
    num_patterns: usize,
    ascii_case_insensitive: bool,
    dfa: bool,
    match_kind: MatchKind,
) -> Box<AhoCorasick> {
    let mut patterns = Vec::new();

    let mut off = 0usize;
    for i in 0..num_patterns {
        unsafe {
            let len = *patterns_len.offset(i as isize);
            let pattern = ptr_to_string(patterns_ptr + off, len);
            patterns.push(pattern);
            off += len;
        }
    }

    let mut ac = AhoCorasickBuilder::new();
    ac.ascii_case_insensitive(ascii_case_insensitive)
        .match_kind(match_kind);

    if dfa {
        ac.kind(Some(AhoCorasickKind::DFA));
    }

    Box::new(ac.build(patterns).unwrap())
}

#[no_mangle]
pub extern "C" fn delete_matcher(_matcher: Box<AhoCorasick>) {
    // Box takes ownership and will release
}

#[no_mangle]
pub extern "C" fn find_iter(ac: &AhoCorasick, value_ptr: usize, value_len: usize) -> Box<FindIter> {
    let value = ptr_to_string(value_ptr, value_len);
    Box::new(ac.find_iter(value))
}

#[no_mangle]
pub extern "C" fn find_iter_next(
    iter: &mut FindIter,
    pattern: &mut usize,
    start: &mut usize,
    end: &mut usize,
) -> bool {
    iter.next()
        .map(|m| {
            *pattern = m.pattern().as_usize();
            *start = m.start();
            *end = m.end();
            true
        })
        .unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn find_iter_delete(_iter: Box<FindIter>) {
    // Box takes ownership and will release
}

#[no_mangle]
pub extern "C" fn overlapping_iter(
    ac: &AhoCorasick,
    value_ptr: usize,
    value_len: usize,
) -> Box<FindOverlappingIter> {
    let value = ptr_to_string(value_ptr, value_len);
    Box::new(ac.find_overlapping_iter(value))
}

#[no_mangle]
pub extern "C" fn overlapping_iter_next(
    iter: &mut FindOverlappingIter,
    pattern: &mut usize,
    start: &mut usize,
    end: &mut usize,
) -> bool {
    iter.next()
        .map(|m| {
            *pattern = m.pattern().as_usize();
            *start = m.start();
            *end = m.end();
            true
        })
        .unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn overlapping_iter_delete(_iter: Box<FindOverlappingIter>) {
    // Box takes ownership and will release
}

#[no_mangle]
pub extern "C" fn matches(
    ac: &mut AhoCorasick,
    value_ptr: usize,
    value_len: usize,
    limit: usize,
    num: &mut usize,
) -> *const usize {
    let mut matches = Vec::new();
    let value = ptr_to_string(value_ptr, value_len);

    let mut count = 0;
    for value in ac.find_iter(value.as_bytes()) {
        if count == limit {
            break;
        }

        matches.push(value.pattern().as_usize());
        matches.push(value.start());
        matches.push(value.end());

        count += 1;
    }

    let b = matches.into_boxed_slice();
    let ptr = b.as_ptr();
    let len = b.len(); // Same as count since into_boxed_slice() truncates
    std::mem::forget(b);
    *num = len;
    ptr
}

#[no_mangle]
pub extern "C" fn matches_delete(ptr: *const usize, len: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut usize, len, len);
    }
}

/// Returns a string from WebAssembly compatible numeric types representing
/// its pointer and length.
fn ptr_to_string(ptr: usize, len: usize) -> &'static str {
    unsafe {
        let slice = slice::from_raw_parts(ptr as *mut u8, len);
        str::from_utf8_unchecked(slice)
    }
}
