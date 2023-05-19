// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.multiphase_evaluation

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

	"github.com/corazawaf/coraza-proxy-wasm/wasmplugin"
)

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

	vmTestNoMultiPhase(t, func(t *testing.T, vm types.VMContext) {
		for _, tc := range tests {
			tt := tc

			t.Run(tt.name, func(t *testing.T) {
				conf := fmt.Sprintf(`
					{"directives_map": {"default": ["%s"]}, "default_directive": "default"}
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

func vmTestNoMultiPhase(t *testing.T, f func(*testing.T, types.VMContext)) {
	t.Helper()

	t.Run("go", func(t *testing.T) {
		f(t, wasmplugin.NewVMContext())
	})

	t.Run("wasm", func(t *testing.T) {
		buildPath := filepath.Join("build", "mainraw_nomultiphase.wasm")
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
