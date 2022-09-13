// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/tidwall/gjson"
)

type rule struct {
	inline  string
	include string
}

// pluginConfiguration is a type to represent an example configuration for this wasm plugin.
type pluginConfiguration struct {
	rules []rule
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
	rules := jsonData.Get("rules")
	rules.ForEach(func(_, value gjson.Result) bool {
		if inline := value.Get("inline"); inline.Exists() {
			config.rules = append(config.rules, rule{inline: inline.String()})
			return true
		} else if include := value.Get("include"); include.Exists() {
			config.rules = append(config.rules, rule{include: include.String()})
			return true
		} else {
			return false
		}
	})

	return config, nil
}

func resolveIncludes(rs []rule, crsRules fs.FS) (string, error) {
	if len(rs) == 0 {
		return "", nil
	}

	srs := strings.Builder{}
	defer srs.Reset()
	for _, r := range rs {
		switch {
		case r.inline != "":
			srs.WriteString(strings.TrimSpace(r.inline))

		case r.include != "":
			if r.include == "OWASP_CRS" {
				ors := strings.Builder{}

				err := fs.WalkDir(crsRules, ".", func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					if !strings.HasPrefix(path, "REQUEST-") && !strings.HasPrefix(path, "RESPONSE-") {
						return nil
					}

					f, err := crsRules.Open(path)
					if err != nil {
						return fmt.Errorf("failed to open embedded rule %q: %s", path, err.Error())
					}

					fc, err := io.ReadAll(f)
					f.Close()
					if err != nil {
						return fmt.Errorf("failed to read embedded rule file %q: %s", path, err.Error())
					}

					_, err = ors.Write(bytes.TrimSpace(fc))
					return err
				})
				if err != nil {
					return "", fmt.Errorf("failed to walk embedded rules: %s", err.Error())
				}

				owaspCRSContent := strings.TrimSpace(ors.String())
				ors.Reset()
				srs.WriteString(owaspCRSContent)
			} else {
				f, err := crsRules.Open(r.include[len("OWASP_CRS_"):] + ".conf")
				if err != nil {
					return "", fmt.Errorf("failed to open embedded rule %q: %s", r.include, err.Error())
				}
				content, err := io.ReadAll(f)
				f.Close()
				if err != nil {
					return "", fmt.Errorf("failed to read embedded rule file: %s", err.Error())
				}
				content = bytes.TrimSpace(content)
				srs.Write(content)
			}
		default:
			return "", errors.New("empty rule")
		}
		srs.WriteString("\n")
	}

	return strings.TrimSpace(srs.String()), nil
}
