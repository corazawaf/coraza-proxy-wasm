// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"testing"
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
			name: "inline",
			config: `
			{
				"rules": "SecRuleEngine On"
			}
			`,
			expectConfig: pluginConfiguration{
				rules: "SecRuleEngine On",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg, err := parsePluginConfiguration([]byte(testCase.config))
			if want, have := fmt.Sprint(testCase.expectErr), fmt.Sprint(err); want != have {
				t.Errorf("unexpected error, want %q, have %q", want, have)
			}

			if want, have := testCase.expectConfig.rules, cfg.rules; want != have {
				t.Errorf("unexpected rules, want %q, have %q", want, have)
			}
		})
	}
}
