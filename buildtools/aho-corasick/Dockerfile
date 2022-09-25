# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM rust:1-alpine

RUN apk add --no-cache curl patch && rustup target add wasm32-wasi

RUN mkdir -p /aho-corasick && curl -L https://github.com/BurntSushi/aho-corasick/archive/refs/tags/0.7.19.tar.gz | tar -xz --strip-components 1 -C /aho-corasick
WORKDIR /aho-corasick
ADD aho-corasick.patch aho-corasick.patch
RUN patch -p1 < aho-corasick.patch
ENV RUSTFLAGS "-C target-feature=-crt-static"
RUN cargo build --release --target wasm32-wasi

CMD ["cp", "target/wasm32-wasi/release/libaho_corasick.a", "/out/libaho_corasick.a"]