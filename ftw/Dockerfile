# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/coreruleset/go-ftw:0.4.3

RUN apk update && apk add curl

WORKDIR /workspace

ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0-rc1.tar.gz /workspace/coreruleset/
RUN cd coreruleset && tar -xf v4.0.0-rc1.tar.gz --strip-components 1

COPY ftw.yml /workspace/ftw.yml
COPY tests.sh /workspace/tests.sh

ENTRYPOINT ["sh"]
CMD ["-c", "/workspace/tests.sh"]
