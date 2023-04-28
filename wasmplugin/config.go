// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"bytes"
	"fmt"

	"github.com/tidwall/gjson"
)

// pluginConfiguration is a type to represent an example configuration for this wasm plugin.
type pluginConfiguration struct {
	ruleSets             RuleSets
	metricLabels         map[string]string
	defaultRuleSet       string
	perAuthorityRuleSets map[string]string
}

type RuleSets map[string][]string

func parsePluginConfiguration(data []byte) (pluginConfiguration, error) {
	config := pluginConfiguration{}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return config, nil
	}

	if !gjson.ValidBytes(data) {
		return config, fmt.Errorf("invalid json: %q", data)
	}

	jsonData := gjson.ParseBytes(data)

	config.ruleSets = make(RuleSets)
	jsonData.Get("rulesets").ForEach(func(key, value gjson.Result) bool {
		ruleSetName := key.String()
		if _, ok := config.ruleSets[ruleSetName]; ok {
			return true
		}

		var rule []string
		value.ForEach(func(_, value gjson.Result) bool {
			rule = append(rule, value.String())
			return true
		})

		config.ruleSets[ruleSetName] = rule
		return true
	})

	config.metricLabels = make(map[string]string)
	jsonData.Get("metric_labels").ForEach(func(key, value gjson.Result) bool {
		config.metricLabels[key.String()] = value.String()
		return true
	})

	defaultRuleSet := jsonData.Get("default_ruleset")
	if defaultRuleSet.Exists() {
		defaultRuleSetName := defaultRuleSet.String()
		if _, ok := config.ruleSets[defaultRuleSetName]; !ok {
			return config, fmt.Errorf("ruleset not found for default ruleset: %q", defaultRuleSetName)
		}

		config.defaultRuleSet = defaultRuleSetName
	}

	config.perAuthorityRuleSets = make(map[string]string)
	jsonData.Get("per_authority_ruleset").ForEach(func(key, value gjson.Result) bool {
		config.perAuthorityRuleSets[key.String()] = value.String()
		return true
	})

	for authority, ruleSetName := range config.perAuthorityRuleSets {
		if _, ok := config.ruleSets[ruleSetName]; !ok {
			return config, fmt.Errorf("ruleset not found for authority %s: %q", authority, ruleSetName)
		}
	}

	return config, nil
}
