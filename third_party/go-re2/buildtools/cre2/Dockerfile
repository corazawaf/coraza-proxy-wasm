# Copyright (c) 2026 Tigera, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Builds libcre2.a (cre2 C ABI backed by the Rust `regex` crate) for
# wasm32-wasip1, ABI-matched to TinyGo 0.41's wasi-libc. Mirrors the
# wasilibs/go-aho-corasick Rust->wasm->.a recipe (rust image + rustup target +
# cargo build --release), but targets wasm32-wasip1 (Rust renamed wasm32-wasi ->
# wasm32-wasip1) instead of the retired wasm32-wasi.
#
# The output is a wasm32 object archive: architecture-independent, so this
# builds identically on arm64 or amd64 hosts. The `regex` crate + this ~300-line
# shim compile in well under a minute -- no high-core build host required.
#
#   docker build -f Dockerfile -t cre2-rs-build .
#   docker create --name x cre2-rs-build && docker cp x:/out/libcre2.a . && docker rm x
#
# Pin RUST_IMAGE to a toolchain whose bundled wasm32-wasip1 wasi-libc tracks
# TinyGo 0.41's (wasi-libc 1dfe5c30, LLVM 20). Rust >= 1.82 (LLVM >= 19) is
# close; the imported libc symbol surface (malloc/free/memcpy/aligned_alloc) is
# stable across wasi-libc revisions, unlike the C++ libc++ ABI that Variant A
# fought.
# Default matches the coraza-wasm Makefile's RUST_IMAGE (the build path the CI
# actually uses is `make build`, which runs `cargo build` in this image via
# docker; this Dockerfile is the equivalent standalone recipe). Override with
# --build-arg RUST_IMAGE= to A/B a toolchain.
ARG RUST_IMAGE=docker.io/calico/rust-build:1.93.1
FROM ${RUST_IMAGE} AS build

RUN rustup target add wasm32-wasip1

WORKDIR /cre2
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

# System allocator on wasm32-wasip1 imports malloc/free/realloc/aligned_alloc/
# calloc/posix_memalign from libc -- TinyGo satisfies these (see the fork's
# malloc_tinygowasm.go). We do NOT bundle an allocator, so the archive stays a
# thin set of undefined libc refs that TinyGo resolves at wasm-link time.
RUN cargo build --release --target wasm32-wasip1

RUN mkdir -p /out && cp target/wasm32-wasip1/release/libcre2.a /out/libcre2.a

FROM scratch AS artifact
COPY --from=build /out/libcre2.a /libcre2.a
