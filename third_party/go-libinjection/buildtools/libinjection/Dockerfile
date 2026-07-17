# Copyright 2022 The OWASP Coraza contributors
# Modifications Copyright (c) 2026 Tigera, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# TIGERA FORK: bumped wasi-sdk-20 -> wasi-sdk-24 (LLVM 19, ABI-matched to TinyGo
# 0.39's wasi-libc) and forced --target=wasm32-wasip1. Upstream targeted the
# retired wasm32-wasi triple, whose libinjection.a no longer links under TinyGo
# 0.39. See ../../TIGERA-FORK.md.
FROM ghcr.io/webassembly/wasi-sdk:wasi-sdk-24

ENV CFLAGS="-O3 --target=wasm32-wasip1"

RUN apt-get update && apt-get install -y autogen autoconf automake libtool curl

RUN mkdir -p /libinjection && curl -L https://github.com/libinjection/libinjection/archive/4aa3894b21d03d9d8fc364505c0617d2aca73fc1.tar.gz | tar -xz --strip-components 1 -C /libinjection
WORKDIR /libinjection
RUN ./autogen.sh && \
    # host is required by configure but not used so set it arbitrarily
    ./configure --host=i686-pc-linux-gnu --enable-shared=false && \
    make -C src libinjection.la

# Only the static archive (libinjection.a) is shipped: it backs @detectXSS under
# the tinygo build. The wazero-path shared module (libinjection.so) was dropped
# with the wazero path (EV-6833); see ../../TIGERA-FORK.md.
CMD ["cp", "src/.libs/libinjection.a", "/out/"]
