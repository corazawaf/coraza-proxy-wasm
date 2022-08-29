// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These tests are supposed to run with `proxytest` build tag, and this way we can leverage the testing framework in "proxytest" package.
// The framework emulates the expected behavior of Envoyproxy, and you can test your extensions without running Envoy and with
// the standard Go CLI. To run tests, simply run
// go test ./...

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func TestLifecycle(t *testing.T) {
	reqHdrs := [][2]string{
		{":path", "/hello"},
		{":method", "GET"},
		{":authority", "localhost"},
		{"User-Agent", "gotest"},
		{"Content-Type", "application/x-www-form-urlencoded"},
		{"Content-Length", "32"},
	}
	reqBody := []byte(`animal=bear&food=honey&name=pooh`)
	respHdrs := [][2]string{
		{":status", "200"},
		{"Server", "gotest"},
		{"Content-Length", "11"},
		{"Content-Type", "text/plain"},
	}
	respBody := []byte(`Hello, yogi!`)

	tests := []struct {
		name         string
		rules        string
		responded403 bool
	}{
		{
			name: "url accepted",
			rules: `
SecRuleEngine On\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\"
`,
			responded403: false,
		},
		{
			name: "url denied",
			rules: `
SecRuleEngine On\nSecRule REQUEST_URI \"@streq /hello\" \"id:101,phase:1,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "method accepted",
			rules: `
SecRuleEngine On\nSecRule REQUEST_METHOD \"@streq post\" \"id:101,phase:1,t:lowercase,deny\"
`,
			responded403: false,
		},
		{
			name: "method denied",
			rules: `
SecRuleEngine On\nSecRule REQUEST_METHOD \"@streq get\" \"id:101,phase:1,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "request header name accepted",
			rules: `
SecRuleEngine On\nSecRule REQUEST_HEADERS_NAMES \"@streq accept-encoding\" \"id:101,phase:1,t:lowercase,deny\"
`,
			responded403: false,
		},
		{
			name: "request header name denied",
			rules: `
SecRuleEngine On\nSecRule REQUEST_HEADERS_NAMES \"@streq user-agent\" \"id:101,phase:1,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "request header value accepted",
			rules: `
SecRuleEngine On\nSecRule REQUEST_HEADERS:user-agent \"@streq rusttest\" \"id:101,phase:1,t:lowercase,deny\"
`,
			responded403: false,
		},
		{
			name: "request header value denied",
			rules: `
SecRuleEngine On\nSecRule REQUEST_HEADERS:user-agent \"@streq gotest\" \"id:101,phase:1,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "request body accepted",
			rules: `
SecRuleEngine On\nSecRequestBodyAccess On\nSecRule REQUEST_BODY \"name=yogi\" \"id:101,phase:2,t:lowercase,deny\"
`,
			responded403: false,
		},
		{
			name: "request body denied, end of body",
			rules: `
SecRuleEngine On\nSecRequestBodyAccess On\nSecRule REQUEST_BODY \"name=pooh\" \"id:101,phase:2,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "request body denied, start of body",
			rules: `
SecRuleEngine On\nSecRequestBodyAccess On\nSecRule REQUEST_BODY \"animal=bear\" \"id:101,phase:2,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "status accepted",
			rules: `
SecRuleEngine On\nSecRule RESPONSE_STATUS \"500\" \"id:101,phase:3,t:lowercase,deny\"
`,
			responded403: false,
		},
		{
			name: "status denied",
			rules: `
SecRuleEngine On\nSecRule RESPONSE_STATUS \"200\" \"id:101,phase:3,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "response header name accepted",
			rules: `
SecRuleEngine On\nSecRule RESPONSE_HEADERS_NAMES \"@streq transfer-encoding\" \"id:101,phase:3,t:lowercase,deny\"
`,
			responded403: false,
		},
		{
			name: "response header name denied",
			rules: `
SecRuleEngine On\nSecRule RESPONSE_HEADERS_NAMES \"@streq server\" \"id:101,phase:3,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "response header value accepted",
			rules: `
SecRuleEngine On\nSecRule RESPONSE_HEADERS:server \"@streq rusttest\" \"id:101,phase:3,t:lowercase,deny\"
`,
			responded403: false,
		},
		{
			name: "response header value denied",
			rules: `
SecRuleEngine On\nSecRule RESPONSE_HEADERS:server \"@streq gotest\" \"id:101,phase:3,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "response body accepted",
			rules: `
SecRuleEngine On\nSecResponseBodyAccess On\nSecRule RESPONSE_BODY \"@contains pooh\" \"id:101,phase:4,t:lowercase,deny\"
`,
			responded403: false,
		},
		{
			name: "response body denied, end of body",
			rules: `
SecRuleEngine On\nSecResponseBodyAccess On\nSecRule RESPONSE_BODY \"@contains yogi\" \"id:101,phase:4,t:lowercase,deny\"
`,
			responded403: true,
		},
		{
			name: "response body denied, start of body",
			rules: `
SecRuleEngine On\nSecResponseBodyAccess On\nSecRule RESPONSE_BODY \"@contains hello\" \"id:101,phase:4,t:lowercase,deny\"
`,
			responded403: true,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc

			t.Run(tt.name, func(t *testing.T) {
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(fmt.Sprintf(`
					{
						"rules" : "%s"
					}	
				`, strings.TrimSpace(tt.rules))))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				action := host.CallOnRequestHeaders(id, reqHdrs, false)
				require.Equal(t, types.ActionContinue, action)

				// Stream bodies in chunks of 5

				for i := 0; i < len(reqBody); i += 5 {
					eos := i+5 >= len(reqBody)
					var body []byte
					if eos {
						body = reqBody[i:]
					} else {
						body = reqBody[i : i+5]
					}
					action = host.CallOnRequestBody(id, body, eos)
					require.Equal(t, types.ActionContinue, action)
				}

				action = host.CallOnResponseHeaders(id, respHdrs, false)
				require.Equal(t, types.ActionContinue, action)

				for i := 0; i < len(respBody); i += 5 {
					eos := i+5 >= len(respBody)
					var body []byte
					if eos {
						body = respBody[i:]
					} else {
						body = respBody[i : i+5]
					}
					action = host.CallOnResponseBody(id, body, eos)
					require.Equal(t, types.ActionContinue, action)
				}

				// Call OnHttpStreamDone.
				host.CompleteHttpContext(id)

				pluginResp := host.GetSentLocalResponse(id)
				if tt.responded403 {
					require.NotNil(t, pluginResp)
					require.EqualValues(t, 403, pluginResp.StatusCode)
				} else {
					require.Nil(t, pluginResp)
				}
			})
		}
	})
}

func vmTest(t *testing.T, f func(*testing.T, types.VMContext)) {
	t.Helper()

	t.Run("go", func(t *testing.T) {
		f(t, &vmContext{})
	})

	t.Run("wasm", func(t *testing.T) {
		wasm, err := os.ReadFile(filepath.Join("build", "main.wasm"))
		if err != nil {
			t.Skip("wasm not found")
		}
		v, err := proxytest.NewWasmVMContext(wasm)
		require.NoError(t, err)
		defer v.Close()
		f(t, v)
	})
}
