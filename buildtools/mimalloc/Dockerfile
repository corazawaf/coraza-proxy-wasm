# Copyright The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y cmake patch

RUN mkdir -p /mimalloc && curl -L https://github.com/microsoft/mimalloc/archive/refs/tags/v2.0.6.tar.gz | tar -xz --strip-components 1 -C /mimalloc
WORKDIR /mimalloc
RUN mkdir -p out/release && cd out/release && cmake ../.. -DMI_BUILD_SHARED=off -DMI_BUILD_TESTS=off && make && ${RANLIB} libmimalloc.a

CMD ["cp", "./out/release/libmimalloc.a", "/out/libmimalloc.a"]