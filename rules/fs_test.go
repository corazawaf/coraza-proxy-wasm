// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/require"

	"github.com/corazawaf/coraza-proxy-wasm/rules"
)

var (
	basic = []string{
		"SecRuleEngine On",
		"# comments are ignored",
		"SecResponseBodyMimeType text/plain text/html text/xml",
		`SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"`,
	}

	files = []string{
		"Include crs-setup.conf.example",
		"Include @recommended-conf",
		"Include @ftw-conf",
		"Include @owasp_crs/*.conf",
	}

	demo = []string{
		"Include @demo-conf",
		"Include @crs-setup-demo-conf",
	}
)

func TestRulesFS(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		err  bool
	}{
		{"nil", nil, false},
		{"empty", []string{}, false},
		{"basic", basic, false},
		{"files", files, false},
		{"demo", demo, false},
		{"invalid-arg", []string{"SecRuleEngine"}, true},            // Missing argument
		{"invalid-incomplete", []string{"SecRule ARGS:id"}, true},   // Incomplete rule
		{"invalid-file", []string{"Include unexisting.conf"}, true}, // Include unexisting file
		{"invalid-alias", []string{"Include @owasp_crs"}, true},     // Invalid alias usage
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := coraza.NewWAFConfig().WithRootFS(rules.FS)
			for _, r := range tt.in {
				cfg = cfg.WithDirectives(r)
			}

			_, err := coraza.NewWAF(cfg)
			require.Equalf(t, tt.err, err != nil, "failed: %v", err)
		})
	}
}
