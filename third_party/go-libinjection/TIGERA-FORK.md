# Tigera fork of github.com/wasilibs/go-libinjection

Vendored fork of `github.com/wasilibs/go-libinjection` **v0.5.0**, wired in via a
`replace` directive in `gateway/coraza-wasm/go.mod`. It backs the `@detectSQLi`
and `@detectXSS` operators in the coraza-wasm WAF filter (see
`upstream/internal/operators/sqli_tinygo.go` and `xss_tinygo.go`).

## Why fork

The TinyGo migration (spike B') moved coraza-wasm off the EOL TinyGo 0.34
toolchain. Upstream go-libinjection's TinyGo build links a prebuilt
`libinjection.a` compiled for the retired `wasm32-wasi` target against an old
wasi-sdk; it does not link under TinyGo 0.39's wasi-libc. libinjection is C
(not Rust), so it does NOT hit the two-Rust-staticlibs panic-symbol clash the
go-re2 / go-aho-corasick forks fix — it just needs rebuilding against the
matching toolchain.

## What changed vs upstream v0.5.0

- `wasm/libinjection.a` — **rebuilt** for `wasm32-wasip1` with wasi-sdk-24
  (LLVM 19, ABI-matched to TinyGo 0.39's wasi-libc). Same cre2-style C ABI
  symbols (`libinjection_sqli`, `libinjection_xss`) the Go tinygo path calls.
- `buildtools/libinjection/Dockerfile` — `FROM wasi-sdk-20` -> `wasi-sdk-24`,
  `CFLAGS` forced to `--target=wasm32-wasip1` (upstream targeted the retired
  `wasm32-wasi` triple).
- Test files, benchmarks, `mage.go`, `go.work*`, `.github/` — **removed**: not
  needed by a vendored fork compiled only under the `tinygo` build tag.
- **wazero (non-tinygo host) path removed** (EV-6833): `libinjection_wazero.go`,
  `internal/cinjection/cinjection_libinjection_cgo.go`, and the `libinjection.so`
  shared module the Dockerfile used to emit are all **gone**. The Dockerfile now
  builds only `libinjection.a`. All callers
  (`upstream/internal/operators/{xss,sqli}_tinygo.go`) are `//go:build tinygo`,
  so the host path was dead weight. Mirrors the sibling go-re2 fork, which #12731
  trimmed the same way. The fork no longer builds under host Go — by design.
- `CODE_OF_CONDUCT.md`, `README.md` — **removed** (upstream boilerplate; this
  file records the fork). `LICENSE` kept.
- `init_tinygowasm.go` (`#cgo LDFLAGS: -Lwasm -linjection`) is unchanged — this
  is an independent C archive; unlike aho-corasick it does not fold into the
  cre2 crate.
- Everything else (the Go libinjection API, the tinygo path) is upstream v0.5.0
  unchanged.

## Rebuilding the archive

```
cd buildtools/libinjection
docker build -t libinjection-wasip1-build .
docker run --rm -v "$PWD/out":/out libinjection-wasip1-build   # -> out/libinjection.a
# copy libinjection.a -> ../../wasm/libinjection.a
```
The Dockerfile fetches a pinned libinjection commit and builds a `wasm32`
object archive, so it builds identically on any host arch.
