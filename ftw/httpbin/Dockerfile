# Copyright The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

# TODO(anuraaga): Remove this Dockerfile once a new version of the official image is released
FROM golang:1.19-alpine

# https://github.com/mccutchen/go-httpbin/pull/89
RUN go install github.com/anuraaga/go-httpbin/v2/cmd/go-httpbin@b16c71528bc1cf626f122fc528652e435ce20b85

CMD ["go-httpbin"]
