# Copyright The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y cmake

# Enables export of aligned_alloc
# TODO(anuraaga): It seems like this should be set automatically, consider debugging further.
ENV CFLAGS -D__USE_ISOC11 ${CFLAGS}

RUN mkdir -p /mimalloc && curl -L https://github.com/microsoft/mimalloc/archive/d1fff1119a52e15c1c3807efe1077024c39fe70e.tar.gz | tar -xz --strip-components 1 -C /mimalloc
WORKDIR /mimalloc
RUN mkdir -p out/release && cd out/release && cmake ../.. -DMI_BUILD_SHARED=off -DMI_BUILD_TESTS=off && make && ${RANLIB} libmimalloc.a

CMD ["cp", "./out/release/libmimalloc.a", "/out/libmimalloc.a"]
