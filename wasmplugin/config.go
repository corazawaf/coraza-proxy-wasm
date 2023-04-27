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
	rules         []string
	metricsLabels map[string]string
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
	jsonData.Get("rules").ForEach(func(_, rule gjson.Result) bool {
		config.rules = append(config.rules, rule.String())
		return true
	})

	config.metricsLabels = make(map[string]string)
	jsonData.Get("metrics_labels").ForEach(func(key, value gjson.Result) bool {
		config.metricsLabels[key.String()] = value.String()
		return true
	})

	return config, nil
}
