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
			expectConfig: pluginConfiguration{
				directivesMap:          DirectivesMap{},
				metricLabels:           map[string]string{},
				defaultDirective:       "",
				perAuthorityDirectives: map[string]string{},
			},
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
				"directives_map": {
					"default": ["SecRuleEngine On"]
				},
				"default_directive": "default"
			}
			`,
			expectConfig: pluginConfiguration{
				directivesMap: DirectivesMap{
					"default": []string{"SecRuleEngine On"},
				},
				metricLabels:           map[string]string{},
				defaultDirective:       "default",
				perAuthorityDirectives: map[string]string{},
			},
		},
		{
			name: "inline many entries",
			config: `
			{
				"directives_map": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""]
				},
				"default_directive": "default"
			}
			`,
			expectConfig: pluginConfiguration{
				directivesMap: DirectivesMap{
					"default": []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
				},
				metricLabels:           map[string]string{},
				defaultDirective:       "default",
				perAuthorityDirectives: map[string]string{},
			},
		},
		{
			name: "metrics label",
			config: `
			{
				"directives_map": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""]
				},
				"default_directive": "default",
				"metric_labels": {"owner": "coraza","identifier": "global"}
			}
			`,
			expectConfig: pluginConfiguration{
				directivesMap: DirectivesMap{
					"default": []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
				},
				metricLabels: map[string]string{
					"owner":      "coraza",
					"identifier": "global",
				},
				defaultDirective:       "default",
				perAuthorityDirectives: map[string]string{},
			},
		},
		{
			name: "multiple directives_map",
			config: `
			{
				"directives_map": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""],
					"custom-01": ["SecRuleEngine On"],
					"custom-02": ["SecRuleEngine On"]
				},
				"default_directive": "default",
				"metric_labels": {"owner": "coraza","identifier": "global"}
			}
			`,
			expectConfig: pluginConfiguration{
				directivesMap: DirectivesMap{
					"default":   []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
					"custom-02": []string{"SecRuleEngine On"},
					"custom-01": []string{"SecRuleEngine On"},
				},
				metricLabels: map[string]string{
					"owner":      "coraza",
					"identifier": "global",
				},
				defaultDirective:       "default",
				perAuthorityDirectives: map[string]string{},
			},
		},
		{
			name: "multiple directives_map with authority",
			config: `
			{
				"directives_map": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""],
					"custom-01": ["SecRuleEngine On"],
					"custom-02": ["SecRuleEngine On"]
				},
				"default_directive": "default",
				"metric_labels": {"owner": "coraza","identifier": "global"},
				"per_authority_directives": {
					"mydomain.com":"custom-01",
					"mydomain2.com":"custom-02"
				}
			}
			`,
			expectConfig: pluginConfiguration{
				directivesMap: DirectivesMap{
					"default":   []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
					"custom-02": []string{"SecRuleEngine On"},
					"custom-01": []string{"SecRuleEngine On"},
				},
				metricLabels: map[string]string{
					"owner":      "coraza",
					"identifier": "global",
				},
				defaultDirective: "default",
				perAuthorityDirectives: map[string]string{
					"mydomain.com":  "custom-01",
					"mydomain2.com": "custom-02",
				},
			},
		},
		{
			name: "default directive not found",
			config: `
			{
				"directives_map": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""]
				},
				"default_directive": "foo"
			}
			`,
			expectErr: errors.New("directive map not found for default directive: \"foo\""),
		},
		{
			name: "per authority rule set not found",
			config: `
			{
				"directives_map": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""],
					"custom-01": ["SecRuleEngine On"],
					"custom-02": ["SecRuleEngine On"]
				},
				"default_directive": "default",
				"metric_labels": {"owner": "coraza","identifier": "global"},
				"per_authority_directives": {
					"mydomain.com":"custom-01",
					"mydomain2.com":"custom-03"
				}
			}
			`,
			expectErr: errors.New("directive map not found for authority mydomain2.com: \"custom-03\""),
		},
		{
			name: "backward compatibility with rules",
			config: `
			{ 
				"rules": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""]
			}
			`,
			expectConfig: pluginConfiguration{
				directivesMap: DirectivesMap{
					"default": []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
				},
				defaultDirective:       "default",
				metricLabels:           map[string]string{},
				perAuthorityDirectives: map[string]string{},
			},
		},
		{
			name: "prefer directives instead of rules",
			config: `
			{ 
				"rules": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /rules\" \"id:101,phase:1,t:lowercase,deny\""],
				"directives_map": {
					"foo": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /directives\" \"id:101,phase:1,t:lowercase,deny\""]
				},
				"default_directive": "foo"
			}
			`,
			expectConfig: pluginConfiguration{
				directivesMap: DirectivesMap{
					"foo": []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /directives\" \"id:101,phase:1,t:lowercase,deny\""},
				},
				defaultDirective:       "foo",
				metricLabels:           map[string]string{},
				perAuthorityDirectives: map[string]string{},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg, err := parsePluginConfiguration([]byte(testCase.config))
			assert.Equal(t, testCase.expectErr, err)

			if testCase.expectErr == nil {
				assert.Equal(t, testCase.expectConfig.directivesMap, cfg.directivesMap)
				assert.Equal(t, testCase.expectConfig.metricLabels, cfg.metricLabels)
				assert.Equal(t, testCase.expectConfig.defaultDirective, cfg.defaultDirective)
				assert.Equal(t, testCase.expectConfig.perAuthorityDirectives, cfg.perAuthorityDirectives)
			}
		})
	}
}
