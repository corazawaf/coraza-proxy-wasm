# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

RUN git clone https://github.com/tinygo-org/tinygo --branch dev
WORKDIR /tinygo
RUN git fetch origin && git reset --hard 268140ae40185f2b2b79df9e0550cc4f7287692c
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
