# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/coreruleset/go-ftw:1.3.0

RUN apk update && apk add curl

WORKDIR /workspace

# Keep this CRS version aligned with the one embedded in wasmplugin/rules
ARG CRS_VERSION=v4.13.0

ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz /workspace/coreruleset/
RUN cd coreruleset && tar -xf ${CRS_VERSION}.tar.gz --strip-components 1

COPY ftw.yml /workspace/ftw.yml
COPY tests.sh /workspace/tests.sh

ENTRYPOINT ["sh"]
CMD ["-c", "/workspace/tests.sh"]

