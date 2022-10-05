# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

# https://github.com/tinygo-org/tinygo/commit/9e4e182615cd80303c564f95020e0c3bd10af64a
RUN git clone https://github.com/tinygo-org/tinygo --branch dev
WORKDIR /tinygo
RUN git reset --hard 9e4e182615cd80303c564f95020e0c3bd10af64a
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
