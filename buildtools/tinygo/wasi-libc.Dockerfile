# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

# https://github.com/tinygo-org/tinygo/pull/3280
RUN git clone https://github.com/anuraaga/tinygo --branch wasm-stacks-nogc
WORKDIR /tinygo
RUN git fetch origin wasm-stacks-nogc && git reset --hard e2da8f6f0f5cf5a75a384bbddae80c1b8a84eca7
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
