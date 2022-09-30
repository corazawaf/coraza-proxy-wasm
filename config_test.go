// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"embed"
	"fmt"
	"io/fs"
	"testing"
)

//go:embed testdata/fake_crs
var fakeCRS embed.FS

func getFakeCRS(t *testing.T) fs.FS {
	subCRS, err := fs.Sub(fakeCRS, "testdata/fake_crs")
	if err != nil {
		t.Fatalf("failed to access CRS filesystem: %s", err.Error())
	}
	return subCRS
}

func TestResolveIncludesEntireOWASPCRS(t *testing.T) {
	rs := []rule{
		{
			inline: "SecRuleEngine On",
		},
		{
			include: "OWASP_CRS",
		},
	}

	srs, err := resolveIncludes(rs, getFakeCRS(t))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	expectedRules := `SecRuleEngine On
# just a comment`

	if want, have := expectedRules, srs; want != have {
		t.Errorf("unexpected rules, want %q, have %q", want, have)
	}
}

func TestResolveIncludesSingleCRS(t *testing.T) {
	rs := []rule{
		{
			inline: "SecRuleEngine On",
		},
		{
			include: "OWASP_CRS_REQUEST-911",
		},
	}
	srs, err := resolveIncludes(rs, getFakeCRS(t))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	expectedRules := `SecRuleEngine On
# just a comment`

	if want, have := expectedRules, srs; want != have {
		t.Errorf("unexpected rules, want %q, have %q", want, have)
	}
}

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
				"rules": [
					{
						"inline": "SecRuleEngine On"
					}
				]
			}
			`,
			expectConfig: pluginConfiguration{
				rules: []rule{
					{inline: "SecRuleEngine On"},
				},
			},
		},
		{
			name: "include",
			config: `
			{
				"rules": [
					{
						"include": "OWASP_CRS_SOMETHING"
					}
				]
			}
			`,
			expectConfig: pluginConfiguration{
				rules: []rule{
					{include: "OWASP_CRS_SOMETHING"},
				},
			},
		},
		{
			name: "inline & include",
			config: `
			{
				"rules": [
					{ "inline": "SecRuleEngine On" },
					{
						"include": "OWASP_CRS_SOMETHING"
					},
					{ "inline": "SecRuleEngine Off" }
				]
			}
			`,
			expectConfig: pluginConfiguration{
				rules: []rule{
					{inline: "SecRuleEngine On"},
					{include: "OWASP_CRS_SOMETHING"},
					{inline: "SecRuleEngine Off"},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg, err := parsePluginConfiguration([]byte(testCase.config))
			if want, have := fmt.Sprint(testCase.expectErr), fmt.Sprint(err); want != have {
				t.Errorf("unexpected error, want %q, have %q", want, have)
			}

			if want, have := len(testCase.expectConfig.rules), len(cfg.rules); want != have {
				t.Errorf("unexpected number of rules, want %d, have %d", want, have)
			}

			for i, r := range testCase.expectConfig.rules {
				if want, have := r, cfg.rules[i]; want != have {
					t.Errorf("unexpected rules, want %q, have %q", want, have)
				}
			}
		})
	}
}
