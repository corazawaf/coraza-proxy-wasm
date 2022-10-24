# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

# https://github.com/tinygo-org/tinygo/pull/3245
RUN git clone https://github.com/anuraaga/tinygo --branch customgc
WORKDIR /tinygo
RUN git fetch origin && git reset --hard 8e62159e36217975bdf27cfb4271c2ad2d252441
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
