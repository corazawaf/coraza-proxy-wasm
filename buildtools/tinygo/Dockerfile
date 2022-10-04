# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

ARG TARGETARCH

RUN curl -L https://go.dev/dl/go1.19.1.linux-${TARGETARCH:-amd64}.tar.gz | tar -xz

ENV PATH /go/bin:/root/go/bin:$PATH
ENV GOROOT /go

RUN apt-get install -y libclang-14-dev wabt binaryen git

# https://github.com/tinygo-org/tinygo/commit/9e4e182615cd80303c564f95020e0c3bd10af64a
RUN git clone --shallow-submodules --recursive https://github.com/tinygo-org/tinygo --branch dev
WORKDIR /tinygo
RUN git reset --hard 9e4e182615cd80303c564f95020e0c3bd10af64a
RUN go install
RUN make wasi-libc
