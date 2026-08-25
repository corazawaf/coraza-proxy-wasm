# Tigera fork of github.com/wasilibs/go-re2

Vendored fork of `github.com/wasilibs/go-re2` **v1.6.0**, wired in via a
`replace` directive in `gateway/coraza-wasm/go.mod`. It backs the `@rx`
operator in the coraza-wasm WAF filter (see
`upstream/internal/operators/rx_tinygo.go`).

## Why fork

Spike B' migrated coraza-wasm off the EOL TinyGo 0.34 toolchain. Upstream
go-re2's TinyGo build links a prebuilt `libcre2.a` compiled from Google RE2's
C++, pinned to TinyGo 0.34's wasi-libc ABI; it does not link under newer TinyGo
(LLVM/wasi-libc skew, and the 0.34-era malloc shim collides with the malloc
family newer TinyGo's wasi-libc now provides). Rebuilding RE2's C++ for the new
wasi-libc drags in the libc++ / libc++abi ABI. Instead this fork swaps the RE2
C++ engine for the Rust `regex` crate behind the same cre2 C ABI -- linear-time,
no C++, and (crucially) a non-recursive parser, so the full CRS ruleset compiles
without the stack overflow that stdlib `regexp` hits on TinyGo.

## What changed vs upstream v1.6.0

- `internal/wasm/libcre2.a` -- **replaced**: now built from the Rust `regex`
  crate (`buildtools/cre2/`), not RE2's C++. Same cre2 C ABI symbols go-re2's
  tinygo path calls.
- `internal/wasm/{libre2.a,libc++.a,libc++abi.a}` -- **deleted**: the Rust
  archive is self-contained (compiler_builtins covers the softfloat/int128
  routines); only `libclang_rt.builtins-wasm32.a` is kept as a belt-and-braces
  fallback.
- `malloc_tinygowasm.go` -- **deleted**: it reimplemented `posix_memalign` /
  `__libc_*` for TinyGo 0.34, which lacked them. Newer TinyGo's wasi-libc
  provides them, so the shim now causes duplicate-symbol link errors.
- `init_tinygowasm.go` -- LDFLAGS trimmed to `-Linternal/wasm -lcre2` (Rust's
  compiler_builtins cover the softfloat/int128 routines, so libclang_rt is not
  needed either).
- The **wazero / `!tinygo` host path is removed** (`internal/re2_wazero*.go`,
  `internal/alloc`, `internal/memory`, and the `.so`/`memory.*` blobs). The WAF
  only ever builds go-re2 under the `tinygo` tag, so the fork is tinygo-only.
- `buildtools/cre2/` -- **new**: the Rust crate (Cargo.toml, src/lib.rs) and its
  `Dockerfile` build recipe for `libcre2.a`. See that dir.
- Everything else (the Go re2 API, the tinygo binding) is upstream v1.6.0.

## Rebuilding the archive

`libcre2.a` is committed under `internal/wasm/`, the same way upstream go-re2
ships its prebuilt archive. Rebuild it from `buildtools/cre2` by hand:

```
cd buildtools/cre2
cargo build --release --locked --target wasm32-wasip1
cp target/wasm32-wasip1/release/libcre2.a ../../internal/wasm/libcre2.a
```
The output is a `wasm32` object archive, so it builds identically on any host
arch. See `buildtools/cre2/Dockerfile` for the pinned toolchain.

## @rx pattern compatibility (RE2 vs the Rust `regex` crate)

CRS is written for RE2, and the Rust `regex` crate is an RE2-family engine, so
the ruleset compiles. The shim's `sanitize_re2_escapes` bridges the three
divergences the CRS 4.14 `@rx` patterns actually hit (`\<`/`\>` -> literal, a
non-repetition `{` -> `\{`, and short `\x{HH}` -> `\xHH` in bytes mode).

RE2 syntax that the Rust `regex` crate does **not** support is *not* rewritten,
so a pattern using it fails to compile. That surfaces as a **ruleset load error
at `proxy_on_configure`**, and the filter is configured **fail-closed** (a plugin
that fails to load blocks traffic; it does not allow-all). Known unsupported
features, relevant to hand-written / custom SecRules more than to CRS itself:

- `\Q...\E` literal-quote spans
- `\C` (match any single byte)
- octal escapes (`\0`, `\123`)
- `\x{...}` with more than two hex digits in a Latin1 / arbitrary-bytes pattern

If you migrate a custom `@rx` rule that uses one of these, rewrite it to a
Rust-`regex`-supported form (e.g. `\Q...\E` -> escape the literal chars).
