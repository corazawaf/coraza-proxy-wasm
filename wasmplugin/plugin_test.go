// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"testing"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func TestRetrieveAddressInfo(t *testing.T) {
	testCases := map[string]struct {
		address          []byte
		port             []byte
		expectedTargetIP string
		expectedPort     int
	}{
		"empty": {
			expectedTargetIP: "",
			expectedPort:     0,
		},
		"127.0.0.1:8080": {
			address:          []byte("127.0.0.10:8080"),
			expectedTargetIP: "127.0.0.10",
			expectedPort:     8080,
		},
		"127.0.0.1:8080 with port": {
			address:          []byte("127.0.0.11:8080"),
			port:             []byte{5, 10, 0, 0, 0, 0, 0, 0}, // 256*10 + 5
			expectedTargetIP: "127.0.0.11",
			expectedPort:     2565,
		},
	}

	for _, target := range []string{"source", "destination"} {
		t.Run(target, func(t *testing.T) {
			for name, tCase := range testCases {
				t.Run(name, func(t *testing.T) {
					opt := proxytest.
						NewEmulatorOption().
						WithVMContext(NewVMContext())

					host, reset := proxytest.NewHostEmulator(opt)
					defer reset()

					require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

					id := host.InitializeHttpContext()

					if len(tCase.address) > 0 {
						err := host.SetProperty([]string{target, "address"}, []byte(tCase.address))
						require.NoError(t, err)
					}

					if len(tCase.port) > 0 {
						err := host.SetProperty([]string{target, "port"}, []byte(tCase.port))
						require.NoError(t, err)
					}

					targetIP, port := retrieveAddressInfo(debuglog.Nop(), target)
					assert.Equal(t, tCase.expectedTargetIP, targetIP)
					assert.Equal(t, tCase.expectedPort, port)

					host.CompleteHttpContext(id)
				})
			}
		})
	}
}
