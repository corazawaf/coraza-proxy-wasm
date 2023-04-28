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
				ruleSets:             RuleSets{},
				metricLabels:         map[string]string{},
				defaultRuleSet:       "",
				perAuthorityRuleSets: map[string]string{},
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
				"rulesets": {
					"default": ["SecRuleEngine On"]
				},
				"default_ruleset": "default"
			}
			`,
			expectConfig: pluginConfiguration{
				ruleSets: RuleSets{
					"default": []string{"SecRuleEngine On"},
				},
				metricLabels:         map[string]string{},
				defaultRuleSet:       "default",
				perAuthorityRuleSets: map[string]string{},
			},
		},
		{
			name: "inline many entries",
			config: `
			{
				"rulesets": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""]
				},
				"default_ruleset": "default"
			}
			`,
			expectConfig: pluginConfiguration{
				ruleSets: RuleSets{
					"default": []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
				},
				metricLabels:         map[string]string{},
				defaultRuleSet:       "default",
				perAuthorityRuleSets: map[string]string{},
			},
		},
		{
			name: "metrics label",
			config: `
			{
				"rulesets": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""]
				},
				"default_ruleset": "default",
				"metric_labels": {"owner": "coraza","identifier": "global"}
			}
			`,
			expectConfig: pluginConfiguration{
				ruleSets: RuleSets{
					"default": []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
				},
				metricLabels: map[string]string{
					"owner":      "coraza",
					"identifier": "global",
				},
				defaultRuleSet:       "default",
				perAuthorityRuleSets: map[string]string{},
			},
		},
		{
			name: "multiple rulesets",
			config: `
			{
				"rulesets": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""],
					"custom-01": ["SecRuleEngine On"],
					"custom-02": ["SecRuleEngine On"]
				},
				"default_ruleset": "default",
				"metric_labels": {"owner": "coraza","identifier": "global"}
			}
			`,
			expectConfig: pluginConfiguration{
				ruleSets: RuleSets{
					"default":   []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
					"custom-02": []string{"SecRuleEngine On"},
					"custom-01": []string{"SecRuleEngine On"},
				},
				metricLabels: map[string]string{
					"owner":      "coraza",
					"identifier": "global",
				},
				defaultRuleSet:       "default",
				perAuthorityRuleSets: map[string]string{},
			},
		},
		{
			name: "multiple rulesets with authority",
			config: `
			{
				"rulesets": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""],
					"custom-01": ["SecRuleEngine On"],
					"custom-02": ["SecRuleEngine On"]
				},
				"default_ruleset": "default",
				"metric_labels": {"owner": "coraza","identifier": "global"},
				"per_authority_ruleset": {
					"mydomain.com":"custom-01",
					"mydomain2.com":"custom-02"
				}
			}
			`,
			expectConfig: pluginConfiguration{
				ruleSets: RuleSets{
					"default":   []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
					"custom-02": []string{"SecRuleEngine On"},
					"custom-01": []string{"SecRuleEngine On"},
				},
				metricLabels: map[string]string{
					"owner":      "coraza",
					"identifier": "global",
				},
				defaultRuleSet: "default",
				perAuthorityRuleSets: map[string]string{
					"mydomain.com":  "custom-01",
					"mydomain2.com": "custom-02",
				},
			},
		},
		{
			name: "default ruleset not found",
			config: `
			{
				"rulesets": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""]
				},
				"default_ruleset": "foo"
			}
			`,
			expectErr: errors.New("ruleset not found for default ruleset: \"foo\""),
		},
		{
			name: "per authority rule set not found",
			config: `
			{
				"rulesets": {
					"default": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""],
					"custom-01": ["SecRuleEngine On"],
					"custom-02": ["SecRuleEngine On"]
				},
				"default_ruleset": "default",
				"metric_labels": {"owner": "coraza","identifier": "global"},
				"per_authority_ruleset": {
					"mydomain.com":"custom-01",
					"mydomain2.com":"custom-03"
				}
			}
			`,
			expectErr: errors.New("ruleset not found for authority mydomain2.com: \"custom-03\""),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg, err := parsePluginConfiguration([]byte(testCase.config))
			assert.Equal(t, testCase.expectErr, err)

			if testCase.expectErr == nil {
				assert.Equal(t, testCase.expectConfig.ruleSets, cfg.ruleSets)
				assert.Equal(t, testCase.expectConfig.metricLabels, cfg.metricLabels)
				assert.Equal(t, testCase.expectConfig.defaultRuleSet, cfg.defaultRuleSet)
				assert.Equal(t, testCase.expectConfig.perAuthorityRuleSets, cfg.perAuthorityRuleSets)
			}
		})
	}
}
