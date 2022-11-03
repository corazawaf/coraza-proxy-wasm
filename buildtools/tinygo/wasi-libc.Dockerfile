# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

RUN git clone https://github.com/tinygo-org/tinygo
WORKDIR /tinygo
RUN git fetch origin && git reset --hard bce0516394f7446598d169867c31a708443dd2a4
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
