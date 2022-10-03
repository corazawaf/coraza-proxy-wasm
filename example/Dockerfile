# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM curlimages/curl
USER root

WORKDIR /workspace

RUN apk add --no-cache bash

COPY readme-tests.sh /workspace/e2e-example.sh

ENV ENVOY_HOST=envoy
ENV HTTPBIN_HOST=httpbin

ENTRYPOINT ["bash"]
CMD ["-c", "/workspace/e2e-example.sh envoy"]
