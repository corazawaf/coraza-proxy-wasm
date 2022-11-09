# Copyright The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y autogen autoconf automake libtool patch

RUN mkdir -p /bdwgc && curl -L https://github.com/ivmai/bdwgc/archive/refs/tags/v8.2.2.tar.gz | tar -xz --strip-components 1 -C /bdwgc
WORKDIR /bdwgc
ADD bdwgc.patch bdwgc.patch
RUN patch -p1 < bdwgc.patch
RUN ./autogen.sh

# -D_WASI_EMULATED_MMAN allows wasi-libc's mmap header files to be included. We do not actually use
# the library itself, instead reimplementing in mmap.go
ENV CFLAGS ${CFLAGS} -D_WASI_EMULATED_MMAN

# host is required by configure but not used so set it arbitrarily
RUN ./configure --disable-threads --enable-mmap --disable-shared --disable-gcj-support --disable-java-finalization --disable-atomic-uncollectible --host=i686-pc-linux-gnu
RUN make

CMD ["cp", "/bdwgc/.libs/libcord.a", "/bdwgc/.libs/libgc.a", "/out/"]