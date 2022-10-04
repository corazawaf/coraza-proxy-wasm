# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM --platform=linux/amd64 ${WASI_LIBC_IMAGE:-ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-tinygo-wasi-libc:main} AS wasi-libc

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

ARG TARGETARCH

RUN curl -L https://go.dev/dl/go1.19.1.linux-${TARGETARCH:-amd64}.tar.gz | tar -xz

ENV PATH /go/bin:/root/go/bin:$PATH
ENV GOROOT /go

RUN apt-get install -y libclang-14-dev wabt binaryen

COPY --from=wasi-libc /tinygo /tinygo
WORKDIR /tinygo
RUN go install
