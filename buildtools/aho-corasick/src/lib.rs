// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

extern crate aho_corasick;

use std::mem::MaybeUninit;
use std::slice;
use std::str;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

#[no_mangle]
pub unsafe extern "C" fn new_matcher(patterns_ptr: *mut u8, patterns_len: usize) -> Box<AhoCorasick> {
    let all_patterns = unsafe {
        slice::from_raw_parts(patterns_ptr, patterns_len)
    };

    let mut patterns = Vec::new();

    let mut off = 0;
    while off < patterns_len {
        let pattern_len = u32::from_le_bytes([all_patterns[off], all_patterns[off+1], all_patterns[off+2], all_patterns[off+3]]) as usize;
        off += 4;
        let pattern = unsafe {
            str::from_utf8_unchecked(&all_patterns[off..off+pattern_len])
        };
        patterns.push(pattern);
        off += pattern_len;
    }

    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .dfa(true)
        .match_kind(MatchKind::LeftmostLongest)
        .build(patterns);

    return Box::new(ac)
}

#[no_mangle]
pub extern "C" fn matches(ac: &mut AhoCorasick, value_ptr: usize, value_len: usize, n: usize, matches: *mut usize) -> usize {
    let value = ptr_to_string(value_ptr, value_len);

    let mut num = 0;
    for value in ac.find_iter(value) {
        if num == n {
            break;
        }
        unsafe {
            *matches.offset(2*num as isize) = value.start();
            *matches.offset((2*num+1) as isize) = value.end();
        }
        num += 1;
    }

    return num
}

/// WebAssembly export that allocates a pointer (linear memory offset) that can
/// be used for a string.
///
/// This is an ownership transfer, which means the caller must call
/// [`deallocate`] when finished.
#[cfg_attr(all(target_arch = "wasm32"), export_name = "allocate")]
#[no_mangle]
pub extern "C" fn _allocate(size: usize) -> *mut u8 {
    allocate(size as usize)
}

/// Allocates size bytes and leaks the pointer where they start.
fn allocate(size: usize) -> *mut u8 {
    // Allocate the amount of bytes needed.
    let vec: Vec<MaybeUninit<u8>> = Vec::with_capacity(size);

    // into_raw leaks the memory to the caller.
    Box::into_raw(vec.into_boxed_slice()) as *mut u8
}


/// WebAssembly export that deallocates a pointer of the given size (linear
/// memory offset, byteCount) allocated by [`allocate`].
#[cfg_attr(all(target_arch = "wasm32"), export_name = "deallocate")]
#[no_mangle]
pub unsafe extern "C" fn _deallocate(ptr: usize, size: usize) {
    deallocate(ptr as *mut u8, size);
}

/// Retakes the pointer which allows its memory to be freed.
unsafe fn deallocate(ptr: *mut u8, size: usize) {
    let _ = Vec::from_raw_parts(ptr, 0, size);
}

/// Returns a string from WebAssembly compatible numeric types representing
/// its pointer and length.
fn ptr_to_string(ptr: usize, len: usize) -> &'static str {
    unsafe {
        let slice = slice::from_raw_parts_mut(ptr as *mut u8, len as usize);
        return str::from_utf8_unchecked_mut(slice);
    }
}
