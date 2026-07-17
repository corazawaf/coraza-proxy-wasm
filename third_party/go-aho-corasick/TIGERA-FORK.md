# Tigera fork of github.com/wasilibs/go-aho-corasick

Vendored fork of `github.com/wasilibs/go-aho-corasick` **v0.6.0**, wired in via a
`replace` directive in `gateway/coraza-wasm/go.mod`. It backs the `@pm` /
`@pmFromFile` operators in the coraza-wasm WAF filter (see
`upstream/internal/operators/pm_tinygo.go`).

## Why fork

The TinyGo migration (spike B') moved coraza-wasm off the EOL TinyGo 0.34
toolchain. Upstream go-aho-corasick's TinyGo build links a prebuilt
`libaho_corasick.a` (a Rust staticlib) and ships a 0.34-era `aligned_alloc`
malloc shim. Neither survives the move:

- **Two Rust staticlibs can't co-link.** `@rx` is served by the go-re2 fork,
  whose `libcre2.a` is now a Rust `regex` archive
  (`../go-re2/buildtools/cre2`). Linking a *second* Rust staticlib
  (`libaho_corasick.a`) into the same TinyGo wasm makes `wasm-ld` hit duplicate
  std panic-runtime symbols (`rust_eh_personality`,
  `std::panicking::EMPTY_PANIC`) — each archive carries its own copy of std —
  and TinyGo 0.39's `wasm-ld` (LLVM 19) has no `--allow-multiple-definition`.
- **The malloc shim collides.** `malloc_tinygowasm.go` reimplemented
  `aligned_alloc` for TinyGo 0.34, which lacked it. Newer TinyGo's wasi-libc
  provides it, so the shim now causes a duplicate-symbol link error (same class
  of failure the go-re2 fork fixed).

## What changed vs upstream v0.6.0

- `wasm/libaho_corasick.a` — **deleted**: the aho-corasick C ABI
  (`new_matcher` / `find_iter` / `matches` / ...) is now compiled into the cre2
  Rust crate (`../go-re2/buildtools/cre2/src/ahocorasick.rs`) so the whole wasm
  links against ONE Rust archive. Those symbols resolve from `libcre2.a` at the
  final wasm link — go-re2's cgo `LDFLAGS` (`-Linternal/wasm -lcre2`) puts that
  archive on the shared link line, and archive-member resolution is global
  across the link, so this package's cgo references find them there.
- `malloc_tinygowasm.go` — **deleted** (see above).
- `init_tinygowasm.go` — dropped the `#cgo LDFLAGS: -Lwasm -laho_corasick`; the
  file is now a doc breadcrumb.
- Test files, testdata, benchmarks, `mage.go`, `go.work*`, `.github/` —
  **removed**: not needed by a vendored fork compiled only under the `tinygo`
  build tag.
- **wazero (non-tinygo host) path removed** (EV-6833): `aho_corasick_wazero.go`,
  the 1.5 MB `wasm/aho_corasick.wasm` blob it embedded, `buildtools/aho-corasick/`
  (the Rust recipe that built that blob), and `init_cgo.go` are all **deleted**.
  This fork is compiled only under the `tinygo` build tag here (all callers in
  `upstream/internal/operators/*_tinygo.go` are `//go:build tinygo`), so the host
  runtime path was dead weight. Mirrors the sibling go-re2 fork, which #12731
  trimmed the same way. The fork no longer builds under host Go — by design.
- `CODE_OF_CONDUCT.md`, `README.md` — **removed** (upstream boilerplate; this
  file records the fork). `LICENSE` kept.
- Everything else (the Go aho-corasick API, the tinygo path) is upstream v0.6.0
  unchanged.

## Rebuilding

The tinygo-path symbols are part of `libcre2.a`; rebuild that archive from
`../go-re2/buildtools/cre2` (its `Dockerfile`). This fork ships no `.a` of its
own.
