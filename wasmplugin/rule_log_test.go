// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRuleLogFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    ruleLogFormat
		wantErr bool
	}{
		{in: "", want: ruleLogFormatBracket},
		{in: "bracket", want: ruleLogFormatBracket},
		{in: "BRACKET", want: ruleLogFormatBracket},
		{in: "json", want: ruleLogFormatJSON},
		{in: " JSON ", want: ruleLogFormatJSON},
		{in: "yaml", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseRuleLogFormat(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestParsePluginConfigurationRuleLogFormat(t *testing.T) {
	cfg, err := parsePluginConfiguration([]byte(`{
		"rule_log_format": "json",
		"directives_map": {"default": ["SecRuleEngine On"]},
		"default_directives": "default"
	}`), func(string) {})
	require.NoError(t, err)
	require.Equal(t, ruleLogFormatJSON, cfg.ruleLogFormat)

	_, err = parsePluginConfiguration([]byte(`{
		"rule_log_format": "invalid",
		"directives_map": {"default": ["SecRuleEngine On"]},
		"default_directives": "default"
	}`), func(string) {})
	require.Error(t, err)
}
