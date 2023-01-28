// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"

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
		name               string
		inlineRules        string
		requestHdrsAction  types.Action
		requestBodyAction  types.Action
		responseHdrsAction types.Action
		responded403       bool
		respondedNullBody  bool
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
		// {
		// 	name: "request body accepted, no access",
		// 	inlineRules: `
		// SecRuleEngine On\nSecRequestBodyAccess Off\nSecRule REQUEST_BODY \"animal=bear\" \"id:101,phase:2,t:lowercase,deny\"
		// `,
		// 	requestHdrsAction:  types.ActionContinue,
		// 	requestBodyAction:  types.ActionContinue,
		// 	responseHdrsAction: types.ActionContinue,
		// 	responded403:       false,
		// 	respondedNullBody:  false,
		// },
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
			SecRuleEngine On\nSecResponseBodyAccess On\nSecRule RESPONSE_BODY \"@contains pooh\" \"id:101,phase:4,t:lowercase,deny\"
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
			SecRuleEngine On\nSecResponseBodyAccess On\nSecRule RESPONSE_BODY \"@contains yogi\" \"id:101,phase:4,t:lowercase,deny\"
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
			SecRuleEngine On\nSecResponseBodyAccess On\nSecRule RESPONSE_BODY \"@contains hello\" \"id:101,phase:4,t:lowercase,deny\"
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
			SecRuleEngine On\nSecResponseBodyAccess Off\nSecRule RESPONSE_BODY \"@contains hello\" \"id:101,phase:4,t:lowercase,deny\"
			`,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
			respondedNullBody:  false,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc

			t.Run(tt.name, func(t *testing.T) {
				conf := `{}`
				if inlineRules := strings.TrimSpace(tt.inlineRules); inlineRules != "" {
					conf = fmt.Sprintf(`{"rules": ["%s"]}`, inlineRules)
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
					for i := 0; i < len(reqBody); i += 5 {
						eos := i+5 >= len(reqBody)
						var body []byte
						if eos {
							body = reqBody[i:]
						} else {
							body = reqBody[i : i+5]
						}
						requestBodyAction = host.CallOnRequestBody(id, body, eos)
						if eos {
							requireEqualAction(t, tt.requestBodyAction, requestBodyAction, "unexpected body action, want %q, have %q on end of stream")
						} else {
							requireEqualAction(t, types.ActionPause, requestBodyAction, "unexpected body action, want %q, have %q")
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
						case eos:
							requireEqualAction(t, types.ActionContinue, responseBodyAction, "unexpected response body action, want %q, have %q on end of stream")
						case responseBodyAccess:
							requireEqualAction(t, types.ActionPause, responseBodyAction, "unexpected response body action, want %q, have %q on end of stream")
						default:
							requireEqualAction(t, types.ActionContinue, responseBodyAction, "unexpected response body action, want %q, have %q on end of stream")
						}
					}
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
				if tt.respondedNullBody {
					pluginBodyResp := host.GetCurrentResponseBody(id)
					require.NotNil(t, pluginBodyResp)
					require.EqualValues(t, byte('\x00'), pluginBodyResp[0])
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
			msg:  `error parsing plugin configuration:`,
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
			},
			msg: "failed to get :path",
		},
		{
			name: "missing method",
			reqHdrs: [][2]string{
				{":path", "/hello"},
			},
			msg: "failed to get :method",
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc
			t.Run(tt.name, func(t *testing.T) {
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm)

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				action := host.CallOnRequestHeaders(id, tt.reqHdrs, false)
				require.Equal(t, types.ActionContinue, action)

				logs := strings.Join(host.GetCriticalLogs(), "\n")
				require.Contains(t, logs, tt.msg)
			})
		}
	})
}

func TestBadResponse(t *testing.T) {
	tests := []struct {
		name     string
		respHdrs [][2]string
		msg      string
	}{
		{
			name: "missing path",
			respHdrs: [][2]string{
				{"content-length", "12"},
			},
			msg: "failed to get :status",
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc
			t.Run(tt.name, func(t *testing.T) {
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm)

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				action := host.CallOnResponseHeaders(id, tt.respHdrs, false)
				require.Equal(t, types.ActionContinue, action)

				logs := strings.Join(host.GetCriticalLogs(), "\n")
				require.Contains(t, logs, tt.msg)
			})
		}
	})
}

func TestEmptyBody(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.
			NewEmulatorOption().
			WithVMContext(vm).
			WithPluginConfiguration([]byte(`{ "rules": [ "SecRequestBodyAccess On", "SecResponseBodyAccess On" ] }`))

		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		id := host.InitializeHttpContext()

		action := host.CallOnRequestBody(id, []byte{}, false)
		require.Equal(t, types.ActionPause, action)
		action = host.CallOnRequestBody(id, []byte{}, true)
		require.Equal(t, types.ActionContinue, action)

		action = host.CallOnResponseBody(id, []byte{}, false)
		require.Equal(t, types.ActionPause, action)
		action = host.CallOnResponseBody(id, []byte{}, true)
		require.Equal(t, types.ActionContinue, action)

		logs := strings.Join(host.GetCriticalLogs(), "\n")
		require.Empty(t, logs)
	})
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
				conf := fmt.Sprintf(`
{
	"rules" : ["SecRule REQUEST_HEADERS:X-CRS-Test \"@rx ^.*$\" \"id:999999,phase:1,log,severity:%d,msg:'%%{MATCHED_VAR}',pass,t:none\""]
}
`, tt.severity)

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
			WithPluginConfiguration([]byte(`{ "rules": [ "Include @ftw-conf", "Include @recommended-conf", "Include @crs-setup-conf", "Include @owasp_crs/*.conf" ] }`))

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
		name               string
		rules              string
		responseHdrsAction types.Action
		responded403       bool
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
			responseHdrsAction: types.ActionPause,
			responded403:       true,
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
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc

			t.Run(tt.name, func(t *testing.T) {
				conf := fmt.Sprintf(`
					{ "rules": ["%s"] }
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

func TestRetrieveAddressInfo(t *testing.T) {
	var unsetPort = -1
	reqHdrs := [][2]string{
		{":path", "/hello"},
		{":method", "GET"},
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
					conf = fmt.Sprintf(`{"rules": ["%s"]}`, inlineRules)
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

func vmTest(t *testing.T, f func(*testing.T, types.VMContext)) {
	t.Helper()

	t.Run("go", func(t *testing.T) {
		f(t, wasmplugin.NewVMContext())
	})

	t.Run("wasm", func(t *testing.T) {
		buildPath := filepath.Join("build", "mainraw.wasm")
		wasm, err := os.ReadFile(buildPath)
		if err != nil {
			t.Skip("wasm not found")
		}
		v, err := proxytest.NewWasmVMContext(wasm)
		require.NoError(t, err)
		defer v.Close()
		f(t, v)
	})
}
