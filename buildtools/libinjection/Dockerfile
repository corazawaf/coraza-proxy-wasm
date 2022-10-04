# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/corazawaf/coraza-proxy-wasm/buildtools-wasi-sdk:main

RUN apt-get install -y patch

RUN mkdir -p /libinjection && curl -L https://github.com/libinjection/libinjection/archive/49904c42a6e68dc8f16c022c693e897e4010a06c.tar.gz | tar -xz --strip-components 1 -C /libinjection
WORKDIR /libinjection
ADD libinjection.patch libinjection.patch
RUN patch -p1 < libinjection.patch
RUN make -C src libinjection.a

CMD ["cp", "src/libinjection.a", "/out/libinjection.a"]
