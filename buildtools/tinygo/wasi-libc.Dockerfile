# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

RUN git clone https://github.com/anuraaga/tinygo --branch custom-gc
WORKDIR /tinygo
# https://github.com/tinygo-org/tinygo/pull/3302
RUN git fetch origin custom-gc && git reset --hard f58fe76081cf3af88b1743131788b6bc4cc72b94
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
