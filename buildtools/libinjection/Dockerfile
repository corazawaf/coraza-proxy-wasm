# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y autogen autoconf automake libtool

RUN mkdir -p /libinjection && curl -L https://github.com/libinjection/libinjection/archive/bd86522711f6fd2b5f257023e19627fd6c1d5ca0.tar.gz | tar -xz --strip-components 1 -C /libinjection
WORKDIR /libinjection
RUN ./autogen.sh && \
    # host is required by configure but not used so set it arbitrarily
    ./configure --host=i686-pc-linux-gnu --enable-shared=false && \
    make

CMD ["cp", "src/.libs/libinjection.a", "/out/libinjection.a"]
