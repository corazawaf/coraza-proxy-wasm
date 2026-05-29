// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

// TestStreamDoneWithoutResponseHeaders reproduces the case where a stream ends
// without the response-headers phase ever running (local replies, HTTP->HTTPS
// redirects, upstream errors). In that situation OnHttpStreamDone must not flush
// ProcessResponseBody, otherwise coraza rejects the out-of-order call with
// "Skipping anomalous call to ProcessResponseBody. It has been called before
// response headers evaluation", flooding the logs.
func TestStreamDoneWithoutResponseHeaders(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		conf := `{"directives_map": {"default": ["SecRuleEngine On"]}, "default_directives": "default"}`
		opt := proxytest.
			NewEmulatorOption().
			WithVMContext(vm).
			WithPluginConfiguration([]byte(conf))

		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		id := host.InitializeHttpContext()

		// Only the request-headers phase runs; the stream then ends without any
		// response-headers callback, as with a redirect/local-reply/error.
		action := host.CallOnRequestHeaders(id, [][2]string{
			{":path", "/"},
			{":method", "GET"},
			{":authority", "localhost"},
		}, true)
		require.Equal(t, types.ActionContinue, action)

		// OnHttpStreamDone.
		host.CompleteHttpContext(id)

		logs := strings.Join(host.GetWarnLogs(), "\n")
		require.NotContains(t, logs, "anomalous call to ProcessResponseBody",
			"OnHttpStreamDone must not call ProcessResponseBody when the response headers phase never ran")
	})
}
