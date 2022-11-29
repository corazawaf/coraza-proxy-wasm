# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

RUN git clone https://github.com/anuraaga/tinygo --branch custom-gc
WORKDIR /tinygo
# https://github.com/tinygo-org/tinygo/pull/3302
RUN git fetch origin custom-gc && git reset --hard e27e61ed063c4febd053f3e1637e9f89b012ad1f
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
