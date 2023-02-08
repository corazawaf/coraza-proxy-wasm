# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/webassembly/wasi-sdk:wasi-sdk-19

RUN apt-get update && apt-get install -y git

RUN git clone https://github.com/tinygo-org/tinygo --branch dev
WORKDIR /tinygo
# https://github.com/tinygo-org/tinygo/commit/47ca1c037baaa137aeb7387454a9c244d4168896
RUN git fetch origin dev && git reset --hard 47ca1c037baaa137aeb7387454a9c244d4168896
RUN git submodule update --init lib/wasi-libc
RUN make wasi-libc
