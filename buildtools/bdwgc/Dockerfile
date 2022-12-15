# Copyright The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y autogen autoconf automake libtool patch

RUN mkdir -p /bdwgc && curl -L https://github.com/ivmai/bdwgc/archive/128c0ec33dc7b41c1ea40ca27d57821135744182.tar.gz | tar -xz --strip-components 1 -C /bdwgc
WORKDIR /bdwgc
ADD bdwgc.patch bdwgc.patch
RUN patch -p1 < bdwgc.patch
RUN ./autogen.sh

# While signals aren't actually used the header file is included unconditionally. We can enable the header file
# without linking the actual signals library because the functions aren't called.
ENV CFLAGS -D_WASI_EMULATED_SIGNAL ${CFLAGS}

# host is required by configure but not used so set it arbitrarily
RUN ./configure --disable-threads --disable-shared --disable-gcj-support --disable-java-finalization --disable-atomic-uncollectible --host=i686-pc-linux-gnu
RUN make

CMD ["cp", "/bdwgc/.libs/libgc.a", "/out/"]