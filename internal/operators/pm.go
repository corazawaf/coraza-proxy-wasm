// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/rules"

	"github.com/jcchavezs/coraza-wasm-filter/internal/ahocorasick"
)

type pm struct {
	m ahocorasick.Matcher
}

var _ rules.Operator = (*pm)(nil)

func (o *pm) Init(options rules.OperatorOptions) error {
	o.m = ahocorasick.NewMatcher(strings.Split(options.Arguments, " "))
	return nil
}

func (o *pm) Evaluate(tx rules.TransactionState, value string) bool {
	return pmEvaluate(o.m, tx, value)
}

func pmEvaluate(m ahocorasick.Matcher, tx rules.TransactionState, value string) bool {
	matches := m.Matches(value, 8)
	if tx.Capturing() {
		for i, c := range matches {
			tx.CaptureField(i, c)
		}
	}
	return len(matches) > 0
}
