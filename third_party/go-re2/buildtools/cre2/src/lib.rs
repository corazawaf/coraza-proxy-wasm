// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// cre2-shaped C ABI backed by the Rust `regex` crate.
//
// go-re2's TinyGo build (internal/cre2/cre2.go) links against a static archive
// exporting the cre2 C ABI (a C wrapper for Google RE2). Upstream builds that
// archive from RE2's C++; here we implement the exact subset go-re2 calls on top
// of the Rust `regex` crate instead. `regex` is a finite-automata engine:
// linear-time, no backtracking/recursion at match time, and its PARSER uses an
// explicit heap stack (non-recursive, bounded by nest_limit) -- so the deeply
// nested CRS patterns that overflowed TinyGo's fixed wasm stack under stdlib
// `regexp` compile cleanly here.
//
// Only the symbols go-re2's `tinygo.wasm || re2_cgo` path references are
// implemented; the rest of cre2.h is intentionally absent (go-re2 never calls
// it). We use regex::bytes so matches carry byte offsets straight into the
// caller's text buffer, which is what go-re2's readMatch() expects.

use regex::bytes::{Regex, RegexBuilder};
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::{ptr, slice};

// aho-corasick C ABI for coraza's @pm / @pmFromFile operators. Kept in this crate
// (not a separate staticlib) so the whole wasm links against ONE Rust archive --
// two Rust archives collide on std's panic symbols and TinyGo's wasm-ld has no
// --allow-multiple-definition. See src/ahocorasick.rs.
mod ahocorasick;

// cre2_string_t: a (pointer, length) view. For matches, `data` points INTO the
// text buffer passed to cre2_match (not a copy) -- go-re2 computes the match
// offset as (data - text_base).
#[repr(C)]
pub struct Cre2String {
    data: *const c_char,
    length: c_int,
}

// cre2_options_t. Only latin1 + max_mem influence CRS; the rest exist because
// go-re2's newRE() may set them (it never does for the coraza rx path).
pub struct Cre2Options {
    longest_match: bool,
    posix_syntax: bool,
    case_sensitive: bool,
    latin1: bool,
    max_mem: i64,
}

// cre2_regexp_t. Holds the compiled regex, or an error code + arg string kept
// alive for cre2_error_arg (go-re2 copies it out immediately after cre2_new).
pub struct Cre2Regexp {
    re: Option<Regex>,
    error_code: c_int,
    error_arg: Vec<u8>,
}

// cre2 error codes (subset of cre2_error_code_t). go-re2 only distinguishes
// 0 (ok) from non-zero (compile failed) beyond formatting the message.
const CRE2_NO_ERROR: c_int = 0;
const CRE2_ERROR_INTERNAL: c_int = 1;
const CRE2_ERROR_PATTERN_TOO_LARGE: c_int = 15;

// ------------------------------------------------------------------ options

#[no_mangle]
pub extern "C" fn cre2_opt_new() -> *mut Cre2Options {
    Box::into_raw(Box::new(Cre2Options {
        longest_match: false,
        posix_syntax: false,
        case_sensitive: true,
        latin1: false,
        max_mem: 8 << 20,
    }))
}

#[no_mangle]
pub extern "C" fn cre2_opt_delete(opt: *mut Cre2Options) {
    if !opt.is_null() {
        unsafe { drop(Box::from_raw(opt)) };
    }
}

#[no_mangle]
pub extern "C" fn cre2_opt_set_log_errors(_opt: *mut Cre2Options, _flag: c_int) {
    // no-op: the Rust engine never logs to stderr.
}

#[no_mangle]
pub extern "C" fn cre2_opt_set_longest_match(opt: *mut Cre2Options, flag: c_int) {
    if let Some(o) = unsafe { opt.as_mut() } {
        o.longest_match = flag != 0;
    }
}

#[no_mangle]
pub extern "C" fn cre2_opt_set_posix_syntax(opt: *mut Cre2Options, flag: c_int) {
    if let Some(o) = unsafe { opt.as_mut() } {
        o.posix_syntax = flag != 0;
    }
}

#[no_mangle]
pub extern "C" fn cre2_opt_set_case_sensitive(opt: *mut Cre2Options, flag: c_int) {
    if let Some(o) = unsafe { opt.as_mut() } {
        o.case_sensitive = flag != 0;
    }
}

#[no_mangle]
pub extern "C" fn cre2_opt_set_latin1_encoding(opt: *mut Cre2Options) {
    if let Some(o) = unsafe { opt.as_mut() } {
        o.latin1 = true;
    }
}

#[no_mangle]
pub extern "C" fn cre2_opt_set_max_mem(opt: *mut Cre2Options, m: i64) {
    if let Some(o) = unsafe { opt.as_mut() } {
        o.max_mem = m;
    }
}

// -------------------------------------------------------- construct/destruct

#[no_mangle]
pub extern "C" fn cre2_new(
    pattern: *const c_char,
    pattern_len: c_int,
    opt: *const Cre2Options,
) -> *mut Cre2Regexp {
    if pattern.is_null() || pattern_len < 0 {
        return Box::into_raw(Box::new(Cre2Regexp {
            re: None,
            error_code: CRE2_ERROR_INTERNAL,
            error_arg: b"null pattern".to_vec(),
        }));
    }
    let pat_bytes = unsafe { slice::from_raw_parts(pattern as *const u8, pattern_len as usize) };

    // The pattern SOURCE is UTF-8 text (CRS uses \xNN escapes, not raw bytes);
    // latin1 vs unicode only changes how those escapes match at runtime.
    let pat = match std::str::from_utf8(pat_bytes) {
        Ok(s) => s,
        Err(_) => {
            return Box::into_raw(Box::new(Cre2Regexp {
                re: None,
                error_code: CRE2_ERROR_INTERNAL,
                error_arg: b"pattern is not valid UTF-8".to_vec(),
            }))
        }
    };

    let (longest, posix, case_sensitive, latin1, max_mem) = match unsafe { opt.as_ref() } {
        Some(o) => (
            o.longest_match,
            o.posix_syntax,
            o.case_sensitive,
            o.latin1,
            o.max_mem,
        ),
        None => (false, false, true, false, 8 << 20),
    };

    // RE2 vs Rust `regex` escape divergence: RE2 (and thus CRS) treats a backslash
    // before ASCII punctuation as that literal punctuation, so CRS patterns escape
    // '<' and '>' freely (e.g. inside `[^...\<\>...]`). The Rust engine does NOT
    // treat them as literals: OUTSIDE a character class it parses `\<` / `\>` as the
    // word-boundary *assertions* \< / \> -- valid syntax but zero-width, so an
    // unhandled `\<` is a SILENT semantic change (potential fail-open), not a
    // compile error; INSIDE a class it errors "invalid escape sequence". Rewriting
    // them to the literal restores RE2 semantics in both cases -- this is a
    // correctness fix, not just an error workaround, so do not drop it. Every other
    // escape (\\ , \x.., perl classes, escapeable metacharacters like \& \| \~) is
    // passed through unchanged.
    let sanitized = sanitize_re2_escapes(pat);
    let mut builder = RegexBuilder::new(&sanitized);
    builder
        // unicode(false) == RE2 Latin1: \xNN and . operate on raw bytes.
        .unicode(!latin1)
        .case_insensitive(!case_sensitive)
        // RE2 default is leftmost-first (Perl). POSIX/longest are opt-in and
        // never set by the coraza rx path, but honor them if asked.
        .swap_greed(false);
    if max_mem > 0 {
        // RE2's max_mem bounds the compiled program; map onto the regex crate's
        // NFA size limit so the big CRS alternations still compile.
        builder.size_limit(max_mem as usize);
        builder.dfa_size_limit(max_mem as usize);
    }
    // longest / posix (here) and the anchor arg to cre2_match are intentionally
    // unsupported: the coraza @rx path only compiles default (leftmost-first)
    // patterns and only ever matches UNANCHORED. If a future caller relied on RE2
    // longest-match, POSIX syntax, or an anchored cre2_match, these would be
    // SILENTLY ignored (match more than intended -> potential fail-open), so
    // revisit before wiring them up.
    let _ = (longest, posix); // regex crate has no runtime longest/POSIX toggle

    match builder.build() {
        Ok(re) => Box::into_raw(Box::new(Cre2Regexp {
            re: Some(re),
            error_code: CRE2_NO_ERROR,
            error_arg: Vec::new(),
        })),
        Err(e) => {
            let msg = e.to_string();
            // "compiled regex exceeds size limit" -> too-large; else generic.
            let code = if msg.contains("size limit") {
                CRE2_ERROR_PATTERN_TOO_LARGE
            } else {
                CRE2_ERROR_INTERNAL
            };
            Box::into_raw(Box::new(Cre2Regexp {
                re: None,
                error_code: code,
                error_arg: msg.into_bytes(),
            }))
        }
    }
}

// sanitize_re2_escapes bridges the RE2-vs-Rust-`regex` syntax gaps that CRS
// patterns hit. RE2 (and thus CRS) is permissive where the Rust engine differs:
//   1. `\<` / `\>` -> literal `<` / `>`. RE2 has no `\<` / `\>` construct (always
//      literal). The Rust engine parses them as word-boundary *assertions* outside
//      a character class -- zero-width, a silent semantic change / potential
//      fail-open -- and errors inside a class. Rewriting to the literal is a
//      correctness fix in both cases (see cre2_new).
//   2. A `{` that does not begin a valid counted repetition `{n}` / `{n,}` /
//      `{n,m}` is a literal brace in RE2; regex-syntax errors "unclosed counted
//      repetition". We escape those to `\{`.
//   3. `\x{HH}` with 1-2 hex digits -> `\xHH` (see the braced-escape arm below):
//      RE2 Latin1 reads brace-hex as a byte, but the Rust engine rejects the brace
//      form when unicode is disabled.
// Everything else is passed through unchanged, including `\\` (so `\\{` stays an
// escaped backslash followed by a brace we then judge on its own). RE2 features
// the Rust engine lacks (\Q..\E, \C, octal escapes) are NOT rewritten and will
// fail ruleset compile (fail-closed); see TIGERA-FORK.md.
fn sanitize_re2_escapes(pat: &str) -> String {
    let cs: Vec<char> = pat.chars().collect();
    let mut out = String::with_capacity(pat.len() + 8);
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        if c == '\\' {
            if i + 1 >= cs.len() {
                out.push('\\');
                i += 1;
                continue;
            }
            let n = cs[i + 1];
            match n {
                '\\' => {
                    out.push('\\');
                    out.push('\\');
                    i += 2;
                }
                '<' | '>' => {
                    out.push(n); // drop the backslash: RE2 literal
                    i += 2;
                }
                // Braced escapes (\x{..}, \u{..}, \p{..}, \P{..}): keep the whole
                // construct together so the counted-repetition rule below never
                // mistakes the inner `{` for a literal brace. For \x{..} with 1-2
                // hex digits we down-convert to the two-digit `\xHH` form: RE2
                // Latin1 reads `\x{e2}` as the single byte 0xE2, but regex-syntax
                // rejects the brace form when unicode is disabled ("Unicode not
                // allowed here"). `\xHH` means byte 0xHH in bytes mode and the
                // identical codepoint U+00HH in unicode mode, so it is safe both
                // ways. Longer braces (codepoints > 0xFF) only occur in unicode
                // patterns and are copied verbatim.
                'x' | 'u' | 'p' | 'P' if i + 2 < cs.len() && cs[i + 2] == '{' => {
                    let mut j = i + 3;
                    while j < cs.len() && cs[j] != '}' {
                        j += 1;
                    }
                    let content: String = cs[i + 3..j].iter().collect();
                    let hex = !content.is_empty() && content.chars().all(|c| c.is_ascii_hexdigit());
                    if n == 'x' && hex && content.len() <= 2 {
                        out.push('\\');
                        out.push('x');
                        for _ in 0..(2 - content.len()) {
                            out.push('0');
                        }
                        out.push_str(&content);
                    } else {
                        out.push('\\');
                        out.push(n);
                        out.push('{');
                        out.push_str(&content);
                        if j < cs.len() {
                            out.push('}');
                        }
                    }
                    i = if j < cs.len() { j + 1 } else { j };
                }
                _ => {
                    out.push('\\');
                    out.push(n);
                    i += 2;
                }
            }
        } else if c == '{' && !starts_counted_repetition(&cs[i..]) {
            out.push('\\'); // literal brace
            out.push('{');
            i += 1;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

// starts_counted_repetition reports whether cs (which begins with '{') opens a
// valid RE2 counted repetition: '{' digit+ (',' digit*)? '}'. A leading digit is
// required (RE2 treats `{,m}` as a literal, not a repetition).
fn starts_counted_repetition(cs: &[char]) -> bool {
    let mut j = 1; // skip '{'
    let digits_start = j;
    while j < cs.len() && cs[j].is_ascii_digit() {
        j += 1;
    }
    if j == digits_start {
        return false;
    }
    if j < cs.len() && cs[j] == ',' {
        j += 1;
        while j < cs.len() && cs[j].is_ascii_digit() {
            j += 1;
        }
    }
    j < cs.len() && cs[j] == '}'
}

#[no_mangle]
pub extern "C" fn cre2_delete(re: *mut Cre2Regexp) {
    if !re.is_null() {
        unsafe { drop(Box::from_raw(re)) };
    }
}

// ---------------------------------------------------------------- inspection

#[no_mangle]
pub extern "C" fn cre2_error_code(re: *const Cre2Regexp) -> c_int {
    unsafe { re.as_ref() }
        .map(|r| r.error_code)
        .unwrap_or(CRE2_ERROR_INTERNAL)
}

#[no_mangle]
pub extern "C" fn cre2_error_arg(re: *const Cre2Regexp, arg: *mut Cre2String) {
    if let (Some(r), Some(a)) = (unsafe { re.as_ref() }, unsafe { arg.as_mut() }) {
        a.data = r.error_arg.as_ptr() as *const c_char;
        a.length = r.error_arg.len() as c_int;
    }
}

#[no_mangle]
pub extern "C" fn cre2_num_capturing_groups(re: *const Cre2Regexp) -> c_int {
    match unsafe { re.as_ref() }.and_then(|r| r.re.as_ref()) {
        // captures_len() counts group 0 (whole match); cre2 excludes it.
        Some(rx) => (rx.captures_len() as c_int) - 1,
        None => 0,
    }
}

// ------------------------------------------------------------------- matching

#[no_mangle]
pub extern "C" fn cre2_match(
    re: *const Cre2Regexp,
    text: *const c_char,
    textlen: c_int,
    startpos: c_int,
    endpos: c_int,
    _anchor: c_int,
    match_arr: *mut Cre2String,
    nmatch: c_int,
) -> c_int {
    let rx = match unsafe { re.as_ref() }.and_then(|r| r.re.as_ref()) {
        Some(r) => r,
        None => return 0,
    };
    if text.is_null() || textlen < 0 || startpos < 0 || endpos < startpos || endpos > textlen {
        return 0;
    }
    let base = text as *const u8;
    let full = unsafe { slice::from_raw_parts(base, textlen as usize) };
    // Search window [startpos, endpos): slice to endpos, start the search at
    // startpos. Both is_match_at() and captures_at() take surrounding context
    // into account (e.g. \A only matches when start == 0), matching RE2's
    // cre2_match semantics.
    let hay = &full[..endpos as usize];
    let start = startpos as usize;

    // Match-only fast path: coraza's MatchString (hit by every non-capturing CRS
    // rule, on every request) passes a null match array / nmatch 0. is_match_at()
    // skips the capture-tracking engine, which is materially slower; the boolean
    // result is identical to "captures_at() returned Some".
    if match_arr.is_null() || nmatch <= 0 {
        return c_int::from(rx.is_match_at(hay, start));
    }

    let caps = match rx.captures_at(hay, start) {
        Some(c) => c,
        None => return 0,
    };
    let n = nmatch as usize;
    let out = unsafe { slice::from_raw_parts_mut(match_arr, n) };
    for (i, slot) in out.iter_mut().enumerate() {
        match caps.get(i) {
            // data points INTO the caller's text buffer at the match start.
            // An empty-but-participating group has start==end -> non-null
            // pointer, length 0 (distinguishable from a null non-match).
            Some(m) => {
                slot.data = unsafe { base.add(m.start()) } as *const c_char;
                slot.length = (m.end() - m.start()) as c_int;
            }
            None => {
                slot.data = ptr::null();
                slot.length = 0;
            }
        }
    }
    1
}

// -------------------------------------------------------------- named groups

pub struct Cre2NamedGroupsIter {
    entries: Vec<(CString, c_int)>,
    pos: usize,
}

#[no_mangle]
pub extern "C" fn cre2_named_groups_iter_new(re: *const Cre2Regexp) -> *mut Cre2NamedGroupsIter {
    let mut entries = Vec::new();
    if let Some(rx) = unsafe { re.as_ref() }.and_then(|r| r.re.as_ref()) {
        for (i, name) in rx.capture_names().enumerate() {
            if let Some(n) = name {
                if let Ok(cs) = CString::new(n) {
                    entries.push((cs, i as c_int));
                }
            }
        }
    }
    Box::into_raw(Box::new(Cre2NamedGroupsIter { entries, pos: 0 }))
}

#[no_mangle]
pub extern "C" fn cre2_named_groups_iter_next(
    iter: *mut Cre2NamedGroupsIter,
    name: *mut *const c_char,
    index: *mut c_int,
) -> bool {
    let it = match unsafe { iter.as_mut() } {
        Some(i) => i,
        None => return false,
    };
    if it.pos >= it.entries.len() {
        return false;
    }
    let (cs, idx) = &it.entries[it.pos];
    // Pointer stays valid until the next call or iter_delete; go-re2 copies it
    // out immediately (CopyCString).
    unsafe {
        if !name.is_null() {
            *name = cs.as_ptr();
        }
        if !index.is_null() {
            *index = *idx;
        }
    }
    it.pos += 1;
    true
}

#[no_mangle]
pub extern "C" fn cre2_named_groups_iter_delete(iter: *mut Cre2NamedGroupsIter) {
    if !iter.is_null() {
        unsafe { drop(Box::from_raw(iter)) };
    }
}

// The offline enumerator that found the RE2-vs-Rust syntax gaps (a host bin
// compiling every CRS @rx pattern through this exact sanitizer) lives outside
// the shipped crate so the archive stays staticlib-only; see the spike notes.

// ----------------------------------------------- referenced-but-unused stubs
//
// go-re2's Go layer references these (Regexp.ReplaceAll / Consume families), so
// the symbols must resolve at wasm-link time, but the coraza @rx operator only
// ever calls MatchString + FindStringSubmatch -> cre2_match. Returning "no
// match / no replacement" is safe: nothing on the CRS path observes it.

#[no_mangle]
pub extern "C" fn cre2_find_and_consume_re(
    _re: *const Cre2Regexp,
    _text: *mut Cre2String,
    _match_arr: *mut Cre2String,
    _nmatch: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn cre2_global_replace_re(
    _re: *const Cre2Regexp,
    _text_and_target: *mut Cre2String,
    _rewrite: *mut Cre2String,
) -> c_int {
    0
}
