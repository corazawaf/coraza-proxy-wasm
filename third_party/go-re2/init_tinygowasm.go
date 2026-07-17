//go:build tinygo.wasm

package re2

/*
// TIGERA FORK (spike B'): libcre2.a is now the Rust `regex`-backed cre2 shim
// (buildtools/cre2), not the C++ RE2 build. That drops the libre2 / libc++ /
// libc++abi archives entirely -- Rust's compiler_builtins covers the softfloat +
// int128 routines, so only the cre2 archive is needed.
//
// libcre2.a is committed under internal/wasm/ (same as upstream go-re2 ships its
// prebuilt archive). Rebuild it from buildtools/cre2 via that dir's Dockerfile.
//
// The -L path is relative to THIS package's directory (TinyGo resolves a
// relative cgo -L against the package source dir, and does not expand cgo's
// ${SRCDIR}), so `internal/wasm` points at this fork's archive regardless of
// where the build is invoked -- the same convention upstream go-re2 uses.
#cgo LDFLAGS: -Linternal/wasm -lcre2
*/
import "C"
