# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y git

# Includes
# https://github.com/tinygo-org/tinygo/pull/3245
# https://github.com/tinygo-org/tinygo/pull/3252
RUN git clone https://github.com/anuraaga/tinygo --branch coraza-fork
WORKDIR /tinygo
RUN git fetch origin && git reset --hard f20979998e57fc5128fbca823b3897b66467abe1
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
