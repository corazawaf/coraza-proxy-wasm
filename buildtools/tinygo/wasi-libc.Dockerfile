# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

# https://github.com/tinygo-org/tinygo/pull/3245
RUN git clone https://github.com/anuraaga/tinygo --branch customgc
WORKDIR /tinygo
RUN git fetch origin && git reset --hard 4f028a0c1ff0fc58045dbfc25b7be3cb69308dbc
# https://github.com/tinygo-org/tinygo/pull/3246
RUN sed -i 's/LLVM_VERSIONS = 14 13 12 11/LLVM_VERSIONS = 15 14 13 12 11/g' Makefile
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
