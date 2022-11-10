// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/tidwall/gjson"
)

var keywordsDict = map[*regexp.Regexp]string{
	regexp.MustCompile("(?i)include @recommended-conf"): "coraza.conf-recommended.conf",
	regexp.MustCompile("(?i)include @crs-conf"):         "crs-setup.conf.example",
	regexp.MustCompile("(?i)include @owasp_crs"):        "crs",
}

// pluginConfiguration is a type to represent an example configuration for this wasm plugin.
type pluginConfiguration struct {
	rules []string
}

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
	config.rules = []string{}
	jsonData.Get("rules").ForEach(func(_, value gjson.Result) bool {
		config.rules = append(config.rules, handlePluginConfigurationKeywords(value.String()))
		return true
	})
	return config, nil
}

// handlePluginConfigurationKeywords replaces high level configuration keywords
// with the internal paths
func handlePluginConfigurationKeywords(configLine string) string {
	for rxKey, val := range keywordsDict {
		// no limit on replacements to address multiple inlined entries
		configLine = rxKey.ReplaceAllString(configLine, "Include "+val)
	}
	return configLine
}
