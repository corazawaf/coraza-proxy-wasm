# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM rust:1-alpine

RUN rustup target add wasm32-wasi

ADD . /aho-corasick
WORKDIR /aho-corasick
ENV RUSTFLAGS "-C target-feature=-crt-static"
RUN cargo build --release --target wasm32-wasi

CMD ["cp", "target/wasm32-wasi/release/libaho_corasick.a", "/out/libaho_corasick.a"]
