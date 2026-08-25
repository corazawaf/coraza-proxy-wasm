// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

const (
	maxBlockedMatchedDataLen = 256
)

const (
	attackTagPrefix         = "attack-"
	categoryOther           = "other"
	categoryLabelMaxLen     = 63
	corazaEnvoyLogNamespace = "io.coraza.waf"
	blockedRequestLogEvent  = "coraza_waf_blocked_request" // Do not remove, this is required for filtering on OTC
)

func truncateMatchedData(data string) string {
	if utf8.RuneCountInString(data) <= maxBlockedMatchedDataLen {
		return data
	}
	runes := []rune(data)
	return string(runes[:maxBlockedMatchedDataLen])
}

func matchedRuleForInterruption(rules []ctypes.MatchedRule, ruleID int) ctypes.MatchedRule {
	for _, rule := range rules {
		if rule.Rule().ID() == ruleID {
			return rule
		}
	}
	return nil
}

func (ctx *httpContext) filterStateLog(phase interruptionPhase, interruption *ctypes.Interruption) {

	statusCode := interruption.Status
	if statusCode == 0 {
		statusCode = defaultInterruptionStatusCode
	}

	setProperty("event", []byte(blockedRequestLogEvent))
	setProperty("rule_id", []byte(strconv.Itoa(interruption.RuleID)))
	setProperty("phase", []byte(phase.String()))
	setProperty("action", []byte(interruption.Action))
	setProperty("status", []byte(strconv.Itoa(statusCode)))

	if matched := matchedRuleForInterruption(ctx.tx.MatchedRules(), interruption.RuleID); matched != nil {
		setProperty("severity", []byte(matched.Rule().Severity().String()))
		setProperty("category", []byte(categoryFromAttackTags(matched.Rule().Tags())))
		if data := matched.Data(); data != "" {
			setProperty("matched_data", []byte(truncateMatchedData(data)))
		}
		setProperty("client_ip", []byte(matched.ClientIPAddress()))
	}
}

// setProperty sets a filter state property under the Coraza namespace. Empty values
// are skipped since they carry no information and are expected whenever the matched
// rule for an interruption cannot be resolved.
func setProperty(name string, value []byte) {
	if len(value) == 0 {
		return
	}
	keyName := corazaEnvoyLogNamespace + "." + name
	if err := proxywasm.SetProperty([]string{keyName}, value); err != nil {
		proxywasm.LogErrorf("an error happened setting the log property %s: %s", keyName, err)
	}
}

// categoryFromAttackTags verify every category from an attack log to see if it
// matches well known tags, otherwise uses categoryOther
func categoryFromAttackTags(tags []string) string {
	for _, tag := range tags {
		if category, ok := categoryFromAttackTag(tag); ok {
			return category
		}
	}
	return categoryOther
}

// categoryFromAttack extracts the tag from the Coraza/CRS rules, and
// mark them as a proper tag for log metadata/filterstate
func categoryFromAttackTag(tag string) (string, bool) {
	if !strings.HasPrefix(tag, attackTagPrefix) {
		return "", false
	}
	category := strings.TrimPrefix(tag, attackTagPrefix)
	if category == "" {
		return "", false
	}

	if !isValidCategoryLabel(category) {
		return "", false
	}
	return category, true
}

// isValidCategoryLabel filters random category names or invalid that may
// have been added by users as custom CRS rules
func isValidCategoryLabel(category string) bool {
	if category == "" || len(category) > categoryLabelMaxLen {
		return false
	}
	for i, r := range category {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		case r == '-' && i > 0:
		default:
			return false
		}
	}
	return unicode.IsLetter(rune(category[0]))
}
