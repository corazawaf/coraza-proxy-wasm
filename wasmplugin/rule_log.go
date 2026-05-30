// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"encoding/json"
	"fmt"
	"strings"

	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

const (
	ruleLogType          = "coraza_rule_match"
	maxRuleLogFieldBytes = 280
)

type ruleLogFormat string

const (
	ruleLogFormatBracket ruleLogFormat = "bracket"
	ruleLogFormatJSON    ruleLogFormat = "json"
)

func parseRuleLogFormat(value string) (ruleLogFormat, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "bracket":
		return ruleLogFormatBracket, nil
	case "json":
		return ruleLogFormatJSON, nil
	default:
		return "", fmt.Errorf("invalid rule_log_format %q: want bracket or json", value)
	}
}

// newRuleLogCallback returns a Coraza error callback that logs matched rules
// in the configured format at the severity mapped to proxy-wasm log levels.
func newRuleLogCallback(format ruleLogFormat) func(ctypes.MatchedRule) {
	return func(mr ctypes.MatchedRule) {
		msg, err := formatRuleLogMessage(mr, format)
		if err != nil {
			proxywasm.LogWarnf("Failed to format rule log as %s, using bracket format: %v", format, err)
			msg = mr.ErrorLog()
		}

		switch mr.Rule().Severity() {
		case ctypes.RuleSeverityEmergency:
			proxywasm.LogCritical(msg)
		case ctypes.RuleSeverityAlert:
			proxywasm.LogCritical(msg)
		case ctypes.RuleSeverityCritical:
			proxywasm.LogCritical(msg)
		case ctypes.RuleSeverityError:
			proxywasm.LogError(msg)
		case ctypes.RuleSeverityWarning:
			proxywasm.LogWarn(msg)
		case ctypes.RuleSeverityNotice:
			proxywasm.LogInfo(msg)
		case ctypes.RuleSeverityInfo:
			proxywasm.LogInfo(msg)
		case ctypes.RuleSeverityDebug:
			proxywasm.LogDebug(msg)
		}
	}
}

func formatRuleLogMessage(mr ctypes.MatchedRule, format ruleLogFormat) (string, error) {
	if format == ruleLogFormatBracket {
		return mr.ErrorLog(), nil
	}

	bts, err := json.Marshal(buildRuleLogEntry(mr))
	if err != nil {
		return "", err
	}
	return string(bts), nil
}

type ruleLogEntry struct {
	Type         string         `json:"type"`
	ClientIP     string         `json:"client_ip"`
	ServerIP     string         `json:"server_ip"`
	URI          string         `json:"uri"`
	UniqueID     string         `json:"unique_id"`
	Message      string         `json:"message"`
	Data         string         `json:"data,omitempty"`
	Disruptive   bool           `json:"disruptive"`
	Phase        int            `json:"phase"`
	Severity     int            `json:"severity"`
	SeverityName string         `json:"severity_name"`
	Rule         ruleLogRule    `json:"rule"`
	Matches      []ruleLogMatch `json:"matches,omitempty"`
}

type ruleLogRule struct {
	ID       int      `json:"id"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Rev      string   `json:"rev,omitempty"`
	Ver      string   `json:"ver,omitempty"`
	Maturity int      `json:"maturity,omitempty"`
	Accuracy int      `json:"accuracy,omitempty"`
	Operator string   `json:"operator,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

type ruleLogMatch struct {
	Variable string `json:"variable,omitempty"`
	Key      string `json:"key,omitempty"`
	Value    string `json:"value,omitempty"`
	Message  string `json:"message,omitempty"`
	Data     string `json:"data,omitempty"`
}

func buildRuleLogEntry(mr ctypes.MatchedRule) ruleLogEntry {
	rule := mr.Rule()
	severity := rule.Severity()

	entry := ruleLogEntry{
		Type:         ruleLogType,
		ClientIP:     mr.ClientIPAddress(),
		ServerIP:     mr.ServerIPAddress(),
		URI:          mr.URI(),
		UniqueID:     mr.TransactionID(),
		Message:      truncateRuleLogField(ruleMessage(mr)),
		Data:         truncateRuleLogField(mr.Data()),
		Disruptive:   mr.Disruptive(),
		Phase:        int(rule.Phase()),
		Severity:     severity.Int(),
		SeverityName: severity.String(),
		Rule: ruleLogRule{
			ID:       rule.ID(),
			File:     rule.File(),
			Line:     rule.Line(),
			Rev:      rule.Revision(),
			Ver:      rule.Version(),
			Maturity: rule.Maturity(),
			Accuracy: rule.Accuracy(),
			Operator: rule.Operator(),
			Tags:     rule.Tags(),
		},
	}

	for _, md := range mr.MatchedDatas() {
		entry.Matches = append(entry.Matches, ruleLogMatch{
			Variable: md.Variable().Name(),
			Key:      md.Key(),
			Value:    truncateRuleLogField(md.Value()),
			Message:  truncateRuleLogField(md.Message()),
			Data:     truncateRuleLogField(md.Data()),
		})
	}

	return entry
}

func ruleMessage(mr ctypes.MatchedRule) string {
	for _, md := range mr.MatchedDatas() {
		if msg := md.Message(); msg != "" {
			return msg
		}
	}
	return mr.Message()
}

func truncateRuleLogField(value string) string {
	if len(value) <= maxRuleLogFieldBytes {
		return value
	}
	return value[:maxRuleLogFieldBytes]
}
