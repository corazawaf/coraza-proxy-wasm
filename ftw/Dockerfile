# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.19-alpine

WORKDIR /workspace

RUN apk update && apk add curl

RUN go install github.com/fzipi/go-ftw@f5f64a16b3d2bebea600ea070ffd5baa7f36213c

ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0-rc1.tar.gz /workspace/coreruleset/
RUN cd coreruleset && tar -xf v4.0.0-rc1.tar.gz --strip-components 1

COPY ftw.yml /workspace/ftw.yml
COPY tests.sh /workspace/tests.sh

ENTRYPOINT ["sh"]
CMD ["-c", "/workspace/tests.sh"]
