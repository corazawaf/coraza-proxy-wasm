// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func TestTruncateMatchedData(t *testing.T) {
	short := "short payload"
	assert.Equal(t, short, truncateMatchedData(short))

	long := strings.Repeat("x", maxBlockedMatchedDataLen+10)
	truncated := truncateMatchedData(long)
	assert.Len(t, truncated, maxBlockedMatchedDataLen)
	assert.Equal(t, strings.Repeat("x", maxBlockedMatchedDataLen), truncated)

	longMultiByte := strings.Repeat("日", maxBlockedMatchedDataLen+10)
	truncatedMultiByte := truncateMatchedData(longMultiByte)
	assert.Equal(t, maxBlockedMatchedDataLen, utf8.RuneCountInString(truncatedMultiByte))
	assert.True(t, utf8.ValidString(truncatedMultiByte))
	assert.Equal(t, strings.Repeat("日", maxBlockedMatchedDataLen), truncatedMultiByte)
}

func TestCategoryFromAttackTags(t *testing.T) {
	tests := []struct {
		name     string
		tags     []string
		expected string
	}{
		{"no tags", nil, categoryOther},
		{"no attack tag", []string{"language-multi", "OWASP_CRS"}, categoryOther},
		{"valid attack tag", []string{"language-multi", "attack-sqli"}, "sqli"},
		{"picks first valid attack tag", []string{"attack-xss", "attack-sqli"}, "xss"},
		{"empty category after prefix", []string{"attack-"}, categoryOther},
		{"uppercase rejected", []string{"attack-SQLI"}, categoryOther},
		{"leading digit rejected", []string{"attack-1sqli"}, categoryOther},
		{"leading dash rejected", []string{"attack--sqli"}, categoryOther},
		{"digit and dash allowed mid-string", []string{"attack-sq-li2"}, "sq-li2"},
		{"too long rejected", []string{"attack-" + strings.Repeat("a", categoryLabelMaxLen+1)}, categoryOther},
		{"max length allowed", []string{"attack-" + strings.Repeat("a", categoryLabelMaxLen)}, strings.Repeat("a", categoryLabelMaxLen)},
		{"falls back past invalid tag", []string{"attack-1invalid", "attack-sqli"}, "sqli"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, categoryFromAttackTags(tt.tags))
		})
	}
}

func TestFilterStateHasLog(t *testing.T) {
	config := `{
				"directives_map": {
					"default": [
						"SecRuleEngine On",
						"SecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,severity:'CRITICAL',tag:'attack-xss',log,deny,status:403\""
					]
				},
				"default_directives": "default",
				"enable_filter_state_logs": true
				}`

	opt := proxytest.
		NewEmulatorOption().
		WithVMContext(NewVMContext()).
		WithPluginConfiguration([]byte(config))

	host, reset := proxytest.NewHostEmulator(opt)
	defer reset()

	require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

	contextID := host.InitializeHttpContext()

	// Simulate working scenario
	action := host.CallOnRequestHeaders(contextID, [][2]string{
		{":method", "GET"},
		{":path", "/test"},
		{":authority", "xxx.yyy.com"},
	}, false)

	// With failure_policy=allow, we expect the request to continue despite the error
	assert.Equal(t, types.ActionContinue, action)
	// Get the property, should be null as no interruption happened
	_, err := host.GetProperty([]string{"io.coraza.waf.event"})
	assert.Error(t, err, "property should not be found")

	// Now simulate an attack and check if the filter is set
	action = host.CallOnRequestHeaders(contextID, [][2]string{
		{":method", "GET"},
		{":path", "/admin"},
		{":authority", "xxx.yyy.com"},
	}, false)

	assert.Equal(t, types.ActionPause, action)
	expectedProperties := map[string]string{
		"event":    "coraza_waf_blocked_request",
		"action":   "deny",
		"category": "xss",
		"phase":    "http_request_headers",
		"rule_id":  "101",
		"severity": "critical",
		"status":   "403",
	}

	for property, expectedValue := range expectedProperties {
		hostProperty, err := host.GetProperty([]string{"io.coraza.waf." + property})
		assert.NoError(t, err)
		assert.Equal(t, expectedValue, string(hostProperty))
	}
}

func TestFilterStateLogDisabledByDefault(t *testing.T) {
	config := `{
				"directives_map": {
					"default": [
						"SecRuleEngine On",
						"SecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny,status:403\""
					]
				},
				"default_directives": "default"
				}`

	opt := proxytest.
		NewEmulatorOption().
		WithVMContext(NewVMContext()).
		WithPluginConfiguration([]byte(config))

	host, reset := proxytest.NewHostEmulator(opt)
	defer reset()

	require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

	contextID := host.InitializeHttpContext()

	action := host.CallOnRequestHeaders(contextID, [][2]string{
		{":method", "GET"},
		{":path", "/admin"},
		{":authority", "xxx.yyy.com"},
	}, false)

	require.Equal(t, types.ActionPause, action)

	_, err := host.GetProperty([]string{"io.coraza.waf.event"})
	assert.Error(t, err, "no filter state property should be set when enable_filter_state_logs is false")
}

func TestFilterStateLogResponseHeadersPhase(t *testing.T) {
	config := `{
				"directives_map": {
					"default": [
						"SecRuleEngine On",
						"SecRule RESPONSE_HEADERS::status \"@rx 200\" \"id:103,phase:3,t:lowercase,severity:'WARNING',tag:'attack-generic',log,deny,status:406\""
					]
				},
				"default_directives": "default",
				"enable_filter_state_logs": true
				}`

	opt := proxytest.
		NewEmulatorOption().
		WithVMContext(NewVMContext()).
		WithPluginConfiguration([]byte(config))

	host, reset := proxytest.NewHostEmulator(opt)
	defer reset()

	require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

	contextID := host.InitializeHttpContext()

	action := host.CallOnRequestHeaders(contextID, [][2]string{
		{":method", "GET"},
		{":path", "/test"},
		{":authority", "xxx.yyy.com"},
	}, true)
	require.Equal(t, types.ActionContinue, action)

	action = host.CallOnResponseHeaders(contextID, [][2]string{
		{":status", "200"},
	}, false)

	require.Equal(t, types.ActionPause, action)

	expectedProperties := map[string]string{
		"phase":    "http_response_headers",
		"rule_id":  "103",
		"category": "generic",
		"status":   "406",
	}
	for property, expectedValue := range expectedProperties {
		hostProperty, err := host.GetProperty([]string{"io.coraza.waf." + property})
		assert.NoError(t, err)
		assert.Equal(t, expectedValue, string(hostProperty))
	}
}
