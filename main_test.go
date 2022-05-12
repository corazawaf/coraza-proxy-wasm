// These tests are supposed to run with `proxytest` build tag, and this way we can leverage the testing framework in "proxytest" package.
// The framework emulates the expected behavior of Envoyproxy, and you can test your extensions without running Envoy and with
// the standard Go CLI. To run tests, simply run
// go test -tags=proxytest ./...

//go:build proxytest

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func TestHttpHeaders_OnHttpRequestHeaders(t *testing.T) {
	type testCase struct {
		path           string
		expectedAction types.Action
	}

	for name, tCase := range map[string]testCase{
		"not matching URL": {
			path:           "/",
			expectedAction: types.ActionContinue,
		},
		"matching URL": {
			path:           "/admin",
			expectedAction: types.ActionPause,
		},
	} {
		t.Run(name, func(t *testing.T) {
			opt := proxytest.
				NewEmulatorOption().
				WithVMContext(&vmContext{}).
				WithPluginConfiguration([]byte(`
					{
						"rules" : "SecRuleEngine On\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""
					}	
				`))
			host, reset := proxytest.NewHostEmulator(opt)
			defer reset()

			require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

			// Initialize http context.
			id := host.InitializeHttpContext()

			// Call OnHttpRequestHeaders.
			hs := [][2]string{{":path", tCase.path}, {":method", "GET"}}
			action := host.CallOnRequestHeaders(id, hs, false)
			require.Equal(t, tCase.expectedAction, action)

			// Call OnHttpStreamDone.
			host.CompleteHttpContext(id)
		})
	}
}
