# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

# Stick with go-ftw:0.6.4 until CRS tests new format is merged (https://github.com/coreruleset/coreruleset/pull/3369)
FROM ghcr.io/coreruleset/go-ftw:0.6.4

RUN apk update && apk add curl

WORKDIR /workspace

# Keep this CRS version aligned with the one embedded in wasmplugin/rules
ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.3.0.tar.gz /workspace/coreruleset/
RUN cd coreruleset && tar -xf v4.3.0.tar.gz --strip-components 1

COPY ftw.yml /workspace/ftw.yml
COPY tests.sh /workspace/tests.sh

ENTRYPOINT ["sh"]
CMD ["-c", "/workspace/tests.sh"]

