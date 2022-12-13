# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y patch

# Use post-release commit for now as it includes support for no-threads
RUN mkdir -p /re2 && curl -L https://github.com/google/re2/archive/954656f47fe8fb505d4818da1e128417a79ea500.tar.gz | tar -xz --strip-components 1 -C /re2
WORKDIR /re2
ENV RE2_CXXFLAGS -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -I. -DRE2_NO_THREADS
RUN make obj/libre2.a

RUN mkdir -p /cre2 && curl -L https://bitbucket.org/marcomaggi/cre2/downloads/cre2-0.4.0-devel.2.tar.gz | tar -xz --strip-components 1 -C /cre2
WORKDIR /cre2
ADD cre2.patch cre2.patch
RUN patch -p1 < cre2.patch
# host is required by configure but not used so set it arbitrarily
RUN RE2_CFLAGS=-I/re2 RE2_LIBS=/re2/obj ./configure --host=i686-pc-linux-gnu --enable-shared=false && \
    make

CMD ["bash", "-c", "cp /re2/obj/libre2.a /out/libre2.a && cp /cre2/.libs/libcre2.a /out/libcre2.a"]
