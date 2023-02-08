# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

ARG WASI_LIBC_IMAGE
FROM --platform=linux/amd64 ${WASI_LIBC_IMAGE:-ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-tinygo-wasi-libc:main} AS wasi-libc

FROM ghcr.io/webassembly/wasi-sdk:wasi-sdk-19

ARG TARGETARCH

RUN apt-get update && apt-get install -y curl
RUN curl -L https://go.dev/dl/go1.19.2.linux-${TARGETARCH:-amd64}.tar.gz | tar -xz

ENV PATH /go/bin:/root/go/bin:$PATH
ENV GOROOT /go

RUN apt-get update && apt-get install -y libclang-15-dev wabt binaryen

COPY --from=wasi-libc /tinygo /tinygo
WORKDIR /tinygo
RUN go install
