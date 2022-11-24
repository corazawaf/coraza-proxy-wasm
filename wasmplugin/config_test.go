// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePluginConfiguration(t *testing.T) {
	testCases := []struct {
		name         string
		config       string
		expectErr    error
		expectConfig pluginConfiguration
	}{
		{
			name: "empty config",
		},
		{
			name:   "empty json",
			config: "{}",
		},
		{
			name:      "bad config",
			config:    "abc",
			expectErr: errors.New("invalid json: \"abc\""),
		},
		{
			name: "inline",
			config: `
			{
				"rules": ["SecRuleEngine On"]
			}
			`,
			expectConfig: pluginConfiguration{
				rules: []string{"SecRuleEngine On"},
			},
		},
		{
			name: "inline many entries",
			config: `
			{ 
				"rules": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""]
			}
			`,
			expectConfig: pluginConfiguration{
				rules: []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg, err := parsePluginConfiguration([]byte(testCase.config))
			assert.Equal(t, testCase.expectErr, err)
			assert.ElementsMatch(t, testCase.expectConfig.rules, cfg.rules)
		})
	}
}
