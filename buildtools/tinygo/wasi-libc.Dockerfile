# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

RUN git clone https://github.com/tinygo-org/tinygo --branch dev
WORKDIR /tinygo
RUN git fetch origin dev && git reset --hard 4daf4fa0a061e7e3b098a3b2a9d8bf022424c6d3
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
