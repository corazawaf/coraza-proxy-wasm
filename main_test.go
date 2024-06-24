// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"

	"github.com/corazawaf/coraza-proxy-wasm/internal/auditlog"
	"github.com/corazawaf/coraza-proxy-wasm/wasmplugin"
)

func checkTXMetric(t *testing.T, host proxytest.HostEmulator, expectedCounter int) {
	t.Helper()
	value, err := host.GetCounterMetric("waf_filter.tx.total")
	require.NoError(t, err)
	require.Equal(t, uint64(expectedCounter), value)
}

var actionName = map[types.Action]string{
	types.ActionPause:    "pause",
	types.ActionContinue: "continue",
}

func requireEqualAction(t *testing.T, expected types.Action, actual types.Action, msg string) {
	require.Equal(t, expected, actual, msg, actionName[expected], actionName[actual])
}

func TestLifecycle(t *testing.T) {
	reqProtocol := "HTTP/1.1"
	reqHdrs := [][2]string{
		{":path", "/hello?name=panda"},
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
		{"Content-Length", "12"},
		{"Content-Type", "text/plain"},
	}
	respBody := []byte(`Hello, yogi!`)

	tests := []struct {
		name                                string
		inlineRules                         string
		requestHdrsAction                   types.Action
		requestBodyAction                   types.Action
		responseHdrsAction                  types.Action
		responded403                        bool
		responded413                        bool
		respondedNullBody                   bool
		expectResponseRejectSinceFirstChunk bool
	}{
		{
			name:               "no rules",
			inlineRules:        ``,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "url accepted",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "url denied",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_URI \"@streq /hello?name=panda\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionPause,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "method accepted",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_METHOD \"@streq post\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "method denied",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_METHOD \"@streq get\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionPause,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "protocol accepted",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_PROTOCOL \"@streq http/2.0\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
		},
		{
			name: "protocol denied",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_PROTOCOL \"@streq http/1.1\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionPause,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       true,
		},
		{
			name: "request header name accepted",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_HEADERS_NAMES \"@streq accept-encoding\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "request header name denied",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_HEADERS_NAMES \"@streq user-agent\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionPause,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "server name denied",
			inlineRules: `
			SecRuleEngine On\nSecRule SERVER_NAME \"@streq localhost\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionPause,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "request header value accepted",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_HEADERS:user-agent \"@streq rusttest\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "request header value denied",
			inlineRules: `
			SecRuleEngine On\nSecRule REQUEST_HEADERS:user-agent \"@streq gotest\" \"id:101,phase:1,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionPause,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "request body accepted",
			inlineRules: `
			SecRuleEngine On\nSecRequestBodyAccess On\nSecRule REQUEST_BODY \"name=yogi\" \"id:101,phase:2,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "request body denied, end of body",
			inlineRules: `
			SecRuleEngine On\nSecRequestBodyAccess On\nSecRule REQUEST_BODY \"name=pooh\" \"id:101,phase:2,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionPause,
			responseHdrsAction: types.ActionContinue,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "request body denied, start of body",
			inlineRules: `
			SecRuleEngine On\nSecRequestBodyAccess On\nSecRule REQUEST_BODY \"animal=bear\" \"id:101,phase:2,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionPause,
			responseHdrsAction: types.ActionContinue,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "request body accepted, no request body access",
			inlineRules: `
			SecRuleEngine On\nSecRequestBodyAccess Off\nSecRule REQUEST_BODY \"animal=bear\" \"id:101,phase:2,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "request body accepted, payload above process partial",
			inlineRules: `
			SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 2\nSecRequestBodyLimitAction ProcessPartial\nSecRule REQUEST_BODY \"animal=bear\" \"id:101,phase:2,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "request body denied, above limits",
			inlineRules: `
			SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 2\nSecRequestBodyLimitAction Reject\nSecRule REQUEST_BODY \"name=yogi\" \"id:101,phase:2,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionPause,
			responseHdrsAction: types.ActionContinue,
			responded413:       true,
			respondedNullBody:  false,
		},
		{
			name: "status accepted",
			inlineRules: `
			SecRuleEngine On\nSecRule RESPONSE_STATUS \"500\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "status denied",
			inlineRules: `
			SecRuleEngine On\nSecRule RESPONSE_STATUS \"200\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionPause,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "status accepted rx",
			inlineRules: `
			SecRuleEngine On\nSecRule RESPONSE_STATUS \"@rx [^\\d]+\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "status denied rx",
			inlineRules: `
			SecRuleEngine On\nSecRule RESPONSE_STATUS \"@rx [\\d]+\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionPause,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "response header name accepted",
			inlineRules: `
			SecRuleEngine On\nSecRule RESPONSE_HEADERS_NAMES \"@streq transfer-encoding\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "response header name denied",
			inlineRules: `
			SecRuleEngine On\nSecRule RESPONSE_HEADERS_NAMES \"@streq server\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionPause,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "response header value accepted",
			inlineRules: `
			SecRuleEngine On\nSecRule RESPONSE_HEADERS:server \"@streq rusttest\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "response header value denied",
			inlineRules: `
			SecRuleEngine On\nSecRule RESPONSE_HEADERS:server \"@streq gotest\" \"id:101,phase:3,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionPause,
			responded403:       true,
			respondedNullBody:  false,
		},
		{
			name: "response body accepted",
			inlineRules: `
			SecRuleEngine On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\nSecRule RESPONSE_BODY \"@contains pooh\" \"id:101,phase:4,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "response body denied, end of body",
			inlineRules: `
			SecRuleEngine On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\nSecRule RESPONSE_BODY \"@contains yogi\" \"id:101,phase:4,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  true,
		},
		{
			name: "response body denied, start of body",
			inlineRules: `
			SecRuleEngine On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\nSecRule RESPONSE_BODY \"@contains hello\" \"id:101,phase:4,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  true,
		},
		{
			name: "response body accepted, no response body access",
			inlineRules: `
			SecRuleEngine On\nSecResponseBodyAccess Off\nSecResponseBodyMimeType text/plain\nSecRule RESPONSE_BODY \"@contains hello\" \"id:101,phase:4,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "response body accepted, payload above process partial",
			inlineRules: `
			SecRuleEngine On\nSecResponseBodyAccess On\nSecResponseBodyLimit 2\nSecResponseBodyLimitAction ProcessPartial\nSecResponseBodyMimeType text/plain\nSecRule RESPONSE_BODY \"@contains hello\" \"id:101,phase:4,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
		{
			name: "response body denied, above limits",
			inlineRules: `
			SecRuleEngine On\nSecResponseBodyAccess On\nSecResponseBodyLimit 2\nSecResponseBodyLimitAction Reject\nSecResponseBodyMimeType text/plain\nSecRule RESPONSE_BODY \"@contains hello\" \"id:101,phase:4,t:lowercase,deny\"
			`,
			requestHdrsAction:                   types.ActionContinue,
			requestBodyAction:                   types.ActionContinue,
			responseHdrsAction:                  types.ActionContinue,
			responded403:                        false, // proxy-wasm does not support it at phase 4
			respondedNullBody:                   true,
			expectResponseRejectSinceFirstChunk: true,
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

				requestHdrsAction := host.CallOnRequestHeaders(id, reqHdrs, false)
				require.Equal(t, tt.requestHdrsAction, requestHdrsAction)

				checkTXMetric(t, host, 1)

				// Stream bodies in chunks of 5

				if requestHdrsAction == types.ActionContinue {
					totalBodysent := 0
					requestBodyAccess := strings.Contains(tt.inlineRules, "SecRequestBodyAccess On")
					requestBodyProcessPartial := strings.Contains(tt.inlineRules, "SecRequestBodyLimitAction ProcessPartial")
					var requestBodyLimit int
					matches := regexp.MustCompile(`SecRequestBodyLimit (\d+)`).FindStringSubmatch(tt.inlineRules)
					if len(matches) > 1 {
						var err error
						requestBodyLimit, err = strconv.Atoi(matches[1])
						require.NoError(t, err)
					}
					for i := 0; i < len(reqBody); i += 5 {
						eos := i+5 >= len(reqBody)
						var body []byte
						if eos {
							body = reqBody[i:]
						} else {
							body = reqBody[i : i+5]
						}
						totalBodysent += len(body)
						requestBodyAction = host.CallOnRequestBody(id, body, eos)
						switch {
						case eos:
							requireEqualAction(t, tt.requestBodyAction, requestBodyAction, "unexpected body action, want %q, have %q on end of stream")
						// Reject: We expect pause in all cases with action Reject: being the limit reached or not
						case requestBodyAccess && !requestBodyProcessPartial:
							requireEqualAction(t, types.ActionPause, requestBodyAction, "unexpected request body action, want %q, have %q")
						// ProcessPartial: we expect pause until the limit is reached
						case requestBodyAccess && requestBodyProcessPartial && totalBodysent < requestBodyLimit:
							requireEqualAction(t, types.ActionPause, requestBodyAction, "unexpected request body action, want %q, have %q")
						// ProcessPartial: we expect tt.requestBodyAction when the limit is reached
						case requestBodyAccess && requestBodyProcessPartial && totalBodysent >= requestBodyLimit:
							requireEqualAction(t, tt.requestBodyAction, requestBodyAction, "unexpected request body action, want %q, have %q")
						default:
							requireEqualAction(t, types.ActionContinue, requestBodyAction, "unexpected request body action, want %q, have %q")
						}
					}
				}

				if requestBodyAction == types.ActionContinue {
					responseHdrsAction = host.CallOnResponseHeaders(id, respHdrs, false)
					require.Equal(t, tt.responseHdrsAction, responseHdrsAction)
				}

				if responseHdrsAction == types.ActionContinue {
					responseBodyAccess := strings.Contains(tt.inlineRules, "SecResponseBodyAccess On")
					responseBodyProcessPartial := strings.Contains(tt.inlineRules, "SecResponseBodyLimitAction ProcessPartial")
					var responseBodyLimit int
					matches := regexp.MustCompile(`SecResponseBodyLimit (\d+)`).FindStringSubmatch(tt.inlineRules)
					if len(matches) > 1 {
						var err error
						responseBodyLimit, err = strconv.Atoi(matches[1])
						require.NoError(t, err)
					}
					totalBodysent := 0
					for i := 0; i < len(respBody); i += 5 {
						eos := i+5 >= len(respBody)
						var body []byte
						if eos {
							body = respBody[i:]
						} else {
							body = respBody[i : i+5]
						}
						totalBodysent += len(body)
						responseBodyAction := host.CallOnResponseBody(id, body, eos)
						switch {
						// expectResponseRejectLimitActionSinceFirstChunk: writing the first chunk (len(respBody) bytes), it is expected to reach
						// the ResponseBodyLimit with the Action set to Reject. When these conditions happen, ActionContinue will be returned,
						// with the interruption enforced replacing the body with null bytes (checked with tt.respondedNullBody)
						case eos, tt.expectResponseRejectSinceFirstChunk:
							requireEqualAction(t, types.ActionContinue, responseBodyAction, "unexpected response body action, want %q, have %q on end of stream")
						// Reject: We expect pause in all cases with action Reject: being the limit reached or not
						// It would either be paused because we are callectin the body or because the limit was reached and we triggered the action
						case responseBodyAccess && !responseBodyProcessPartial:
							requireEqualAction(t, types.ActionPause, responseBodyAction, "unexpected request body action, want %q, have %q")
						// ProcessPartial: we expect pause until the limit is reached
						case responseBodyAccess && responseBodyProcessPartial && totalBodysent < responseBodyLimit:
							requireEqualAction(t, types.ActionPause, responseBodyAction, "unexpected request body action, want %q, have %q")
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

func TestBadConfig(t *testing.T) {
	tests := []struct {
		name string
		conf string
		msg  string
	}{
		{
			name: "bad json",
			conf: "{",
			msg:  `Failed to parse plugin configuration:`,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc
			t.Run(tt.name, func(t *testing.T) {
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(tt.conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusFailed, host.StartPlugin())

				logs := strings.Join(host.GetCriticalLogs(), "\n")
				require.Contains(t, logs, tt.msg)
			})
		}
	})
}

func TestBadRequest(t *testing.T) {
	tests := []struct {
		name    string
		reqHdrs [][2]string
		msg     string
	}{
		{
			name: "missing path",
			reqHdrs: [][2]string{
				{":method", "GET"},
				{":authority", "localhost"},
			},
			msg: "Failed to get :path",
		},
		{
			name: "missing method",
			reqHdrs: [][2]string{
				{":path", "/hello"},
				{":authority", "localhost"},
			},
			msg: "Failed to get :method",
		},
		{
			name: "missing method and path",
			reqHdrs: [][2]string{
				{":authority", "localhost"},
			},
			msg: "Failed to get :method",
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc
			t.Run(tt.name, func(t *testing.T) {
				conf := `{"directives_map": {"default": []}, "default_directives": "default"}`
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				action := host.CallOnRequestHeaders(id, tt.reqHdrs, false)
				require.Equal(t, types.ActionContinue, action)

				logs := strings.Join(host.GetErrorLogs(), "\n")
				require.Contains(t, logs, tt.msg)
			})
		}
	})
}

func TestBadResponse(t *testing.T) {
	tests := []struct {
		name     string
		reqHdrs  [][2]string
		respHdrs [][2]string
		msg      string
	}{
		{
			name: "missing path",
			respHdrs: [][2]string{
				{"content-length", "12"},
				{":authority", "localhost"},
			},
			reqHdrs: [][2]string{
				{":path", "/hello"},
				{":method", "GET"},
				{":authority", "localhost"},
			},
			msg: "Failed to get :status",
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc
			t.Run(tt.name, func(t *testing.T) {
				conf := `{"directives_map": {"default": []}, "default_directives": "default"}`
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				host.CallOnRequestHeaders(id, tt.reqHdrs, false)

				action := host.CallOnResponseHeaders(id, tt.respHdrs, false)
				require.Equal(t, types.ActionContinue, action)

				logs := strings.Join(host.GetErrorLogs(), "\n")
				require.Contains(t, logs, tt.msg)
			})
		}
	})
}

func TestPerAuthorityDirectives(t *testing.T) {
	tests := []struct {
		name                    string
		reqHdrs                 [][2]string
		conf                    string
		localResponseIsNil      bool
		localResponseStatusCode int
	}{
		{
			name: "authority exist on per_authority_directives",
			reqHdrs: [][2]string{
				{":path", "/rs1"},
				{":method", "GET"},
				{":authority", "foo.example.com"},
			},
			conf:                    `{"directives_map": {"default": ["SecRuleEngine On","SecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""], "rs1": ["SecRuleEngine On","SecRule REQUEST_URI \"@streq /rs1\" \"id:101,phase:1,t:lowercase,deny\""]}, "default_directives": "default", "per_authority_directives":{"foo.example.com":"rs1"}}`,
			localResponseStatusCode: 403,
		},
		{
			name: "authority exist on per_authority_directives but calling allowed path",
			reqHdrs: [][2]string{
				{":path", "/admin"},
				{":method", "GET"},
				{":authority", "foo.example.com"},
			},
			conf:               `{"directives_map": {"default": ["SecRuleEngine On","SecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""], "rs1": ["SecRuleEngine On","SecRule REQUEST_URI \"@streq /rs1\" \"id:101,phase:1,t:lowercase,deny\""]}, "default_directives": "default", "per_authority_directives":{"foo.example.com":"rs1"}}`,
			localResponseIsNil: true,
		},
		{
			name: "authority not exist on per_authority_directives",
			reqHdrs: [][2]string{
				{":path", "/admin"},
				{":method", "GET"},
				{":authority", "bar.example.com"},
			},
			conf:                    `{"directives_map": {"default": ["SecRuleEngine On","SecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""], "rs1": ["SecRuleEngine On","SecRule REQUEST_URI \"@streq /rs1\" \"id:101,phase:1,t:lowercase,deny\""]}, "default_directives": "default", "per_authority_directives":{"foo.example.com":"rs1"}}`,
			localResponseStatusCode: 403,
		},
		{
			name: "authority not exist on per_authority_directives and no default",
			reqHdrs: [][2]string{
				{":path", "/admin"},
				{":method", "GET"},
				{":authority", "bar.example.com"},
			},
			conf:               `{"directives_map": {"rs1": ["SecRuleEngine On","SecRule REQUEST_URI \"@streq /rs1\" \"id:101,phase:1,t:lowercase,deny\""]}, "per_authority_directives":{"foo.example.com":"rs1"}}`,
			localResponseIsNil: true,
		},
		{
			name: "authority not exist on per_authority_directives but calling allowed value",
			reqHdrs: [][2]string{
				{":path", "/rs1"},
				{":method", "GET"},
				{":authority", "bar.example.com"},
			},
			conf:               `{"directives_map": {"default": ["SecRuleEngine On","SecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""], "rs1": ["SecRuleEngine On","SecRule REQUEST_URI \"@streq /rs1\" \"id:101,phase:1,t:lowercase,deny\""]}, "default_directives": "default", "per_authority_directives":{"foo.example.com":"rs1"}}`,
			localResponseIsNil: true,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc
			t.Run(tt.name, func(t *testing.T) {
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(tt.conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				host.CallOnRequestHeaders(id, tt.reqHdrs, false)
				host.CompleteHttpContext(id)

				pluginResp := host.GetSentLocalResponse(id)

				if tt.localResponseIsNil {
					require.Nil(t, pluginResp)
					return
				}

				require.NotNil(t, pluginResp)
				require.EqualValues(t, tt.localResponseStatusCode, pluginResp.StatusCode)
			})
		}
	})
}

func TestEmptyBody(t *testing.T) {
	testCases := []struct {
		title                 string
		isRespBodyProcessable bool
	}{
		{
			title:                 "Response body processable",
			isRespBodyProcessable: true,
		},
		{
			title:                 "Response body NOT processable",
			isRespBodyProcessable: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			vmTest(t, func(t *testing.T, vm types.VMContext) {
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(`{"directives_map": {"default": [ "SecRequestBodyAccess On", "SecResponseBodyAccess On", "SecResponseBodyMimeType text/plain"]}, "default_directives": "default"}`))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()
				host.CallOnRequestHeaders(id, [][2]string{
					{":path", "/hello"},
					{":method", "GET"},
					{":authority", "localhost"},
				}, false)
				action := host.CallOnRequestBody(id, []byte{}, false)
				require.Equal(t, types.ActionPause, action)
				action = host.CallOnRequestBody(id, []byte{}, true)
				require.Equal(t, types.ActionContinue, action)

				if tc.isRespBodyProcessable {
					host.CallOnResponseHeaders(id, [][2]string{
						{":status", "200"},
						{"content-length", "0"},
						{"content-type", "text/plain"}}, false)

					action = host.CallOnResponseBody(id, []byte{}, false)
					require.Equal(t, types.ActionPause, action)
					action = host.CallOnResponseBody(id, []byte{}, true)
					require.Equal(t, types.ActionContinue, action)
				} else {
					// If the ResponseBodyMimeType is not matched, we should just continue and not store the body
					action = host.CallOnResponseBody(id, []byte{}, false)
					require.Equal(t, types.ActionContinue, action)
					action = host.CallOnResponseBody(id, []byte{}, true)
					require.Equal(t, types.ActionContinue, action)
				}
				logs := strings.Join(host.GetCriticalLogs(), "\n")
				require.Empty(t, logs)
			})
		})
	}
}

func TestLogError(t *testing.T) {
	reqHdrs := [][2]string{
		{":path", "/hello"},
		{":method", "GET"},
		{":authority", "localhost"},
		{"X-CRS-Test", "for the win!"},
	}

	tests := []struct {
		severity int
		logs     func(host proxytest.HostEmulator) []string
	}{
		{
			severity: 0,
			logs: func(host proxytest.HostEmulator) []string {
				return host.GetCriticalLogs()
			},
		},
		{
			severity: 1,
			logs: func(host proxytest.HostEmulator) []string {
				return host.GetCriticalLogs()
			},
		},
		{
			severity: 2,
			logs: func(host proxytest.HostEmulator) []string {
				return host.GetCriticalLogs()
			},
		},
		{
			severity: 3,
			logs: func(host proxytest.HostEmulator) []string {
				return host.GetErrorLogs()
			},
		},
		{
			severity: 4,
			logs: func(host proxytest.HostEmulator) []string {
				return host.GetWarnLogs()
			},
		},
		{
			severity: 5,
			logs: func(host proxytest.HostEmulator) []string {
				return host.GetInfoLogs()
			},
		},
		{
			severity: 6,
			logs: func(host proxytest.HostEmulator) []string {
				return host.GetInfoLogs()
			},
		},
		{
			severity: 7,
			logs: func(host proxytest.HostEmulator) []string {
				return host.GetDebugLogs()
			},
		},
	}
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc
			t.Run(fmt.Sprintf("severity %d", tt.severity), func(t *testing.T) {
				conf := fmt.Sprintf(`{"directives_map": {"default": ["SecRule REQUEST_HEADERS:X-CRS-Test \"@rx ^.*$\" \"id:999999,phase:1,log,severity:%d,msg:'%%{MATCHED_VAR}',pass,t:none\""]}, "default_directives": "default"}`, tt.severity)

				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(strings.TrimSpace(conf)))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()
				action := host.CallOnRequestHeaders(id, reqHdrs, false)
				require.Equal(t, types.ActionContinue, action)

				logs := strings.Join(tt.logs(host), "\n")
				require.Contains(t, logs, "for the win!")
			})
		}
	})
}

func TestParseCRS(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.
			NewEmulatorOption().
			WithVMContext(vm).
			WithPluginConfiguration([]byte(`{"directives_map": {"default": [ "Include @ftw-conf", "Include @recommended-conf", "Include @crs-setup-conf", "Include @owasp_crs/*.conf" ]}, "default_directives": "default"}`))

		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())
	})
}

func TestBodyRulesWithoutBody(t *testing.T) {
	reqHdrs := [][2]string{
		{":path", "/hello"},
		{":method", "GET"},
		{":authority", "localhost"},
		{"User-Agent", "gotest"},
		{"Content-Type", "application/x-www-form-urlencoded"},
		{"Content-Length", "32"},
	}
	respHdrs := [][2]string{
		{":status", "200"},
		{"Server", "gotest"},
		{"Content-Length", "11"},
		{"Content-Type", "text/plain"},
	}
	tests := []struct {
		name                  string
		rules                 string
		responseHdrsAction    types.Action
		responded403          bool
		disableWithMultiphase bool
	}{
		{
			name: "url accepted in request body phase",
			rules: `
		SecRuleEngine On\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:2,t:lowercase,deny\"
		`,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
		},
		{
			name: "url denied in request body phase",
			rules: `
SecRuleEngine On\nSecRule REQUEST_URI \"@streq /hello\" \"id:101,phase:2,t:lowercase,deny\"
`,
			responseHdrsAction:    types.ActionPause,
			responded403:          true,
			disableWithMultiphase: true,
		},
		{
			name: "url accepted in response body phase",
			rules: `
		SecRuleEngine On\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:4,t:lowercase,deny\"
		`,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
		},
		{
			name: "url denied in response body phase",
			rules: `
		SecRuleEngine On\nSecRule REQUEST_URI \"@streq /hello\" \"id:101,phase:4,t:lowercase,deny\"
		`,
			responseHdrsAction:    types.ActionContinue,
			responded403:          false,
			disableWithMultiphase: true,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc

			if tt.disableWithMultiphase && multiphaseEvaluation {
				// Skipping test, not compatible with multiphaseEvaluation
				return
			}

			t.Run(tt.name, func(t *testing.T) {
				conf := fmt.Sprintf(`
					{"directives_map": {"default": ["%s"]}, "default_directives": "default"}
				`, strings.TrimSpace(tt.rules))
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				requestHdrsAction := host.CallOnRequestHeaders(id, reqHdrs, false)
				require.Equal(t, types.ActionContinue, requestHdrsAction)

				responseHdrsAction := host.CallOnResponseHeaders(id, respHdrs, false)
				require.Equal(t, tt.responseHdrsAction, responseHdrsAction)

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

func TestResponseProperties(t *testing.T) {
	reqHdrs := [][2]string{
		{"Host", "test.com"},
		{"User-Agent", "curl"},
		{"Accept", "*/*"},
	}
	respHdrs := [][2]string{
		{"Server", "gotest"},
		{"Content-Length", "12"},
		{"Content-Type", "text/plain"},
	}
	testCases := []struct {
		name              string
		status            string
		requestHdrsAction types.Action
	}{
		{
			name:              "Test Response Properties: Pass",
			status:            "200",
			requestHdrsAction: types.ActionContinue,
		},
		{
			name:              "Test Response Properties: Deny due to status",
			status:            "500",
			requestHdrsAction: types.ActionPause,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {

		for _, tc := range testCases {
			tt := tc
			inlineRules := `SecRuleEngine On\nSecRule RESPONSE_STATUS \"500\" \"id:1234,phase:3,deny\"`

			conf := `{}`
			if inlineRules := strings.TrimSpace(inlineRules); inlineRules != "" {
				conf = fmt.Sprintf(`{"directives_map": {"default": ["%s"]}, "default_directives": "default"}`, inlineRules)
			}
			t.Run(tt.name, func(t *testing.T) {
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())
				id := host.InitializeHttpContext()

				require.NoError(t, host.SetProperty([]string{"request", "host"}, []byte("test.com")))
				require.NoError(t, host.SetProperty([]string{"request", "path"}, []byte("/headers")))
				require.NoError(t, host.SetProperty([]string{"request", "method"}, []byte("GET")))

				host.CallOnRequestHeaders(id, reqHdrs, false)

				require.NoError(t, host.SetProperty([]string{"response", "code"}, []byte(tt.status)))

				action := host.CallOnResponseHeaders(id, respHdrs, false)
				require.Equal(t, tt.requestHdrsAction, action)
			})
		}
	})
}

func TestRequestProperties(t *testing.T) {
	reqHdrs := [][2]string{
		{"Host", "test.com"},
		{"User-Agent", "curl"},
		{"Accept", "*/*"},
	}
	testCases := []struct {
		name              string
		host              string
		path              string
		method            string
		requestHdrsAction types.Action
	}{
		{
			name:              "Test Request Properties: Pass",
			host:              "example.com",
			path:              "/",
			method:            "GET",
			requestHdrsAction: types.ActionContinue,
		},
		{
			name:              "Test Request Properties: Deny due to path",
			host:              "example.com",
			path:              "/headers",
			method:            "GET",
			requestHdrsAction: types.ActionPause,
		},
		{
			name:              "Test Request Properties: Deny due to method",
			host:              "example.com",
			path:              "/",
			method:            "HEAD",
			requestHdrsAction: types.ActionPause,
		},
		{
			name:              "Test Request Properties: Deny due to host",
			host:              "test.com",
			path:              "/",
			method:            "GET",
			requestHdrsAction: types.ActionPause,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {

		for _, tc := range testCases {
			tt := tc
			inlineRules := `SecRuleEngine On\nSecRule REQUEST_URI \"@contains header\" \"id:1234,phase:1,deny\"\nSecRule REQUEST_METHOD \"@streq HEAD\" \"id:1235,phase:1,deny\"\nSecRule SERVER_NAME \"@contains test\" \"id:1236,phase:1,deny\"`

			conf := `{}`
			if inlineRules := strings.TrimSpace(inlineRules); inlineRules != "" {
				conf = fmt.Sprintf(`{"directives_map": {"default": ["%s"]}, "default_directives": "default"}`, inlineRules)
			}
			t.Run(tt.name, func(t *testing.T) {
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())
				id := host.InitializeHttpContext()

				require.NoError(t, host.SetProperty([]string{"request", "host"}, []byte(tt.host)))
				require.NoError(t, host.SetProperty([]string{"request", "path"}, []byte(tt.path)))
				require.NoError(t, host.SetProperty([]string{"request", "method"}, []byte(tt.method)))

				action := host.CallOnRequestHeaders(id, reqHdrs, false)
				require.Equal(t, tt.requestHdrsAction, action)
			})
		}
	})
}

func TestRetrieveAddressInfo(t *testing.T) {
	var unsetPort = -1
	reqHdrs := [][2]string{
		{":path", "/hello"},
		{":method", "GET"},
		{":authority", "localhost"},
	}
	testCases := []struct {
		name              string
		addressProperty   string
		portProperty      int
		expectIP          string
		expectPort        int
		requestHdrsAction types.Action
	}{
		{
			name:              "IPv4 parse, usual circumstances",
			addressProperty:   "127.0.0.1:5001",
			portProperty:      50001,
			expectIP:          "127.0.0.1",
			expectPort:        50001,
			requestHdrsAction: types.ActionPause,
		},
		{
			name:              "IPv4 parse, port retrieved from address",
			addressProperty:   "127.0.0.1:5002",
			portProperty:      unsetPort,
			expectIP:          "127.0.0.1",
			expectPort:        50002,
			requestHdrsAction: types.ActionPause,
		},
		{
			name:              "IPv6 parse, usual circumstances",
			addressProperty:   "[2001:db8::1]:8001",
			portProperty:      8001,
			expectIP:          "[2001:db8::1]",
			expectPort:        8001,
			requestHdrsAction: types.ActionPause,
		},
		{
			name:              "IPv6 parse, port retrieved from address",
			addressProperty:   "[2001:db8::1]:8002",
			portProperty:      unsetPort,
			expectIP:          "[2001:db8::1]",
			expectPort:        8002,
			requestHdrsAction: types.ActionPause,
		},
		{
			name:              "No properties retrieved, OnRequestHeaders does not fail",
			addressProperty:   "",
			portProperty:      unsetPort,
			expectIP:          "127.0.0.1",
			expectPort:        80,
			requestHdrsAction: types.ActionContinue,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {

		m := map[string]string{
			"source":      "REMOTE",
			"destination": "SERVER",
		}
		for target, targetSecRuleVariable := range m {

			for _, tc := range testCases {
				tt := tc
				inlineRules := fmt.Sprintf(`
			SecRuleEngine On\nSecRule %s_ADDR \"@ipMatch %s\" \"id:101,phase:1,deny\"\nSecRule %s_PORT \"@eq %d\" \"id:102,phase:1,deny\"
			`, targetSecRuleVariable, tt.expectIP, targetSecRuleVariable, tt.expectPort)

				conf := `{}`
				if inlineRules := strings.TrimSpace(inlineRules); inlineRules != "" {
					conf = fmt.Sprintf(`{"directives_map": {"default": ["%s"]}, "default_directives": "default"}`, inlineRules)
				}
				t.Run(tt.name, func(t *testing.T) {
					opt := proxytest.
						NewEmulatorOption().
						WithVMContext(vm).
						WithPluginConfiguration([]byte(conf))

					host, reset := proxytest.NewHostEmulator(opt)
					defer reset()

					require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())
					id := host.InitializeHttpContext()

					if tt.addressProperty != "" {
						require.NoError(t, host.SetProperty([]string{target, "address"}, []byte(tt.addressProperty)))
					}
					if tt.portProperty != unsetPort {
						buf := new(bytes.Buffer)
						require.NoError(t, binary.Write(buf, binary.LittleEndian, uint64(tt.portProperty)))
						require.NoError(t, host.SetProperty([]string{target, "port"}, buf.Bytes()))
					}
					action := host.CallOnRequestHeaders(id, reqHdrs, false)
					require.Equal(t, tt.requestHdrsAction, action)
				})
			}
		}
	})
}

func TestParseServerName(t *testing.T) {
	testCases := map[string]struct {
		autorityHeader string
		expServerName  string
	}{
		"authority with port": {
			autorityHeader: "coraza.io:443",
			expServerName:  "coraza.io",
		},
		"authority without port": {
			autorityHeader: "coraza.io",
			expServerName:  "coraza.io",
		},
		"IPv6 with port": {
			autorityHeader: "[2001:db8::1]:8080",
			expServerName:  "2001:db8::1",
		},
		"IPv6": {
			autorityHeader: "2001:db8::1",
			expServerName:  "2001:db8::1",
		},
		"bad format": {
			autorityHeader: "hostA:hostB:8080",
			expServerName:  "hostA:hostB:8080",
		},
	}
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for name, tCase := range testCases {
			inlineRules := fmt.Sprintf(`
			SecRuleEngine On\nSecRule SERVER_NAME \"@streq %s\" \"id:101,phase:1,deny\"`, tCase.expServerName)

			conf := `{}`
			if inlineRules := strings.TrimSpace(inlineRules); inlineRules != "" {
				conf = fmt.Sprintf(`{"directives_map": {"default": ["%s"]}, "default_directives": "default"}`, inlineRules)
			}
			t.Run(name, func(t *testing.T) {
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())
				id := host.InitializeHttpContext()
				reqHdrs := [][2]string{
					{":path", "/hello"},
					{":method", "GET"},
					{":authority", tCase.autorityHeader},
				}
				action := host.CallOnRequestHeaders(id, reqHdrs, false)
				require.Equal(t, types.ActionPause, action)
			})
		}
	})
}

func TestHttpConnectRequest(t *testing.T) {
	tests := []struct {
		name     string
		reqHdrs  [][2]string
		logCount int
	}{
		{
			name: "CONNECT",
			reqHdrs: [][2]string{
				{":method", "CONNECT"},
				{":authority", "localhost"},
			},
			logCount: 0,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc
			t.Run(tt.name, func(t *testing.T) {
				conf := `{"directives_map": {"default": []}, "default_directives": "default"}`
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				action := host.CallOnRequestHeaders(id, tt.reqHdrs, false)
				require.Equal(t, types.ActionContinue, action)

				require.Equal(t, len(host.GetErrorLogs()), tt.logCount)
			})
		}
	})
}

func vmTest(t *testing.T, f func(*testing.T, types.VMContext)) {
	t.Helper()

	t.Run("go", func(t *testing.T) {
		auditlog.RegisterProxyWasmSerialWriter()
		f(t, wasmplugin.NewVMContext())
	})

	t.Run("wasm", func(t *testing.T) {
		buildPath := filepath.Join("build", "mainraw.wasm")
		wasm, err := os.ReadFile(buildPath)
		if err != nil {
			t.Fatal("wasm not found")
		}
		v, err := proxytest.NewWasmVMContext(wasm)
		require.NoError(t, err)
		defer v.Close()
		f(t, v)
	})
}
