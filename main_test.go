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
		name               string
		inlineRules        string
		requestHdrsAction  types.Action
		requestBodyAction  types.Action
		responseHdrsAction types.Action
		responded403       bool
	}{
		{
			name:               "no rules",
			inlineRules:        ``,
			requestHdrsAction:  types.ActionContinue,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       false,
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
		},
		{
			name: "url denied",
			inlineRules: `
SecRuleEngine On\nSecRule REQUEST_URI \"@streq /hello\" \"id:101,phase:1,t:lowercase,deny\"
`,
			requestHdrsAction:  types.ActionPause,
			requestBodyAction:  types.ActionContinue,
			responseHdrsAction: types.ActionContinue,
			responded403:       true,
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
		},
	}

	vmTest(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc

			t.Run(tt.name, func(t *testing.T) {
				conf := `{}`
				if inlineRules := strings.TrimSpace(tt.inlineRules); inlineRules != "" {
					conf = fmt.Sprintf(`
					{ 
						"rules": [ { "inline": "%s" } ]
					}	
				`, inlineRules)
				}
				opt := proxytest.
					NewEmulatorOption().
					WithVMContext(vm).
					WithPluginConfiguration([]byte(conf))

				host, reset := proxytest.NewHostEmulator(opt)
				defer reset()

				require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

				id := host.InitializeHttpContext()

				requestBodyAction := types.ActionPause
				responseHdrsAction := types.ActionPause

				requestHdrsAction := host.CallOnRequestHeaders(id, reqHdrs, false)
				require.Equal(t, tt.requestHdrsAction, requestHdrsAction)

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
							require.Equal(t, tt.requestBodyAction, requestBodyAction)
						} else {
							require.Equal(t, types.ActionContinue, requestBodyAction)
						}
					}
				}

				if requestBodyAction == types.ActionContinue {
					responseHdrsAction = host.CallOnResponseHeaders(id, respHdrs, false)
					require.Equal(t, tt.responseHdrsAction, responseHdrsAction)
				}

				if responseHdrsAction == types.ActionContinue {
					for i := 0; i < len(respBody); i += 5 {
						eos := i+5 >= len(respBody)
						var body []byte
						if eos {
							body = respBody[i:]
						} else {
							body = respBody[i : i+5]
						}
						action := host.CallOnResponseBody(id, body, eos)
						require.Equal(t, types.ActionContinue, action)
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
			WithVMContext(vm)

		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		id := host.InitializeHttpContext()

		action := host.CallOnRequestBody(id, []byte{}, false)
		require.Equal(t, types.ActionContinue, action)
		action = host.CallOnRequestBody(id, []byte{}, true)
		require.Equal(t, types.ActionContinue, action)

		action = host.CallOnResponseBody(id, []byte{}, false)
		require.Equal(t, types.ActionContinue, action)
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
	"rules" : [{"inline": "SecRule REQUEST_HEADERS:X-CRS-Test \"@rx ^.*$\" \"id:999999,phase:1,log,severity:%d,msg:'%%{MATCHED_VAR}',pass,t:none\""}]
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
			WithPluginConfiguration([]byte(`{ "rules": [ {"inline": "Include ftw-config.conf\nInclude coraza.conf-recommended\nInclude crs-setup.conf.example\nInclude crs/*.conf"} ] }`))

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
					{ "rules": [ {"inline": "%s"} ] }
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

func vmTest(t *testing.T, f func(*testing.T, types.VMContext)) {
	t.Helper()

	t.Run("go", func(t *testing.T) {
		f(t, &vmContext{})
	})

	t.Run("wasm", func(t *testing.T) {
		buildPath := filepath.Join("build", "main.wasm")
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
