// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"io"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

type ByteLenger interface {
	Len() int
}

// bodyWrapper is a wrapper around the GetHttpRequestBody which exposes
// the length of the body on beforehand so the tx.ReadRequestBodyFrom can
// look at the body length first before attempting to copy the bytes.
type bodyWrapper struct{ totalSize int }

var (
	_ io.Reader  = bodyWrapper{}
	_ ByteLenger = bodyWrapper{}
)

func (w bodyWrapper) Read(p []byte) (int, error) {
	var (
		readingBytes int
		lenErr       error
	)

	if len(p) > readingBytes {
		readingBytes = w.totalSize
		lenErr = io.EOF
	} else {
		readingBytes = len(p)
	}

	body, err := proxywasm.GetHttpRequestBody(0, readingBytes)
	if err != nil {
		return 0, err
	}

	n := copy(p, body)
	return n, lenErr
}

func (w bodyWrapper) Len() int {
	return w.totalSize
}
