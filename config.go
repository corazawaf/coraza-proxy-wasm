// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/tidwall/gjson"
)

var keywordsDict = []keyword{
	{key: "@recommended-conf", tran: "coraza.conf-recommended.conf"},
	{key: "@crs-conf", tran: "crs-setup.conf.example"},
	{key: "@owasp_crs", tran: "crs"},
}

type keyword struct {
	key   string
	tran  string
	keyRx *regexp.Regexp
}

// pluginConfiguration is a type to represent an example configuration for this wasm plugin.
type pluginConfiguration struct {
	rules []string
}

func parsePluginConfiguration(data []byte) (pluginConfiguration, error) {
	config := pluginConfiguration{}
	// initilizes keywords regexes
	for keyId := range keywordsDict {
		keywordsDict[keyId].keyRx = regexp.MustCompile(`(?i)include ` + keywordsDict[keyId].key)
	}

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
	for _, keyw := range keywordsDict {
		// no limit on replacements to address multiple inlined entries
		configLine = keyw.keyRx.ReplaceAllString(configLine, "Include "+keyw.tran)
	}
	return configLine
}
