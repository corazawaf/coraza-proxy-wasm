// These tests are supposed to run with `proxytest` build tag, and this way we can leverage the testing framework in "proxytest" package.
// The framework emulates the expected behavior of Envoyproxy, and you can test your extensions without running Envoy and with
// the standard Go CLI. To run tests, simply run
// go test ./...

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func TestHttpHeaders_OnHttpRequestHeaders(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		expectedAction types.Action
		responded403   bool
	}{
		{
			name:           "not matching URL",
			path:           "/",
			expectedAction: types.ActionContinue,
			responded403:   false,
		},
		{
			name:           "matching URL",
			path:           "/admin",
			expectedAction: types.ActionContinue,
			responded403:   true,
		},
	}

	for _, runner := range []string{"go", "wasm"} {
		t.Run(runner, func(t *testing.T) {
			var vm types.VMContext
			switch runner {
			case "go":
				vm = &vmContext{}
			case "wasm":
				wasm, err := os.ReadFile(filepath.Join("build", "main.wasm"))
				if err != nil {
					t.Skip("wasm not found")
				}
				v, err := proxytest.NewWasmVMContext(wasm)
				require.NoError(t, err)
				vm = v
			}

			for _, tc := range tests {
				tt := tc

				t.Run(tt.name, func(t *testing.T) {
					opt := proxytest.
						NewEmulatorOption().
						WithVMContext(vm).
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
					hs := [][2]string{{":path", tt.path}, {":method", "GET"}}
					action := host.CallOnRequestHeaders(id, hs, false)
					require.Equal(t, tt.expectedAction, action)

					// Call OnHttpStreamDone.
					host.CompleteHttpContext(id)

					if tt.responded403 {
						resp := host.GetSentLocalResponse(id)
						require.EqualValues(t, 403, resp.StatusCode)
					}
				})
			}
		})
	}
}
