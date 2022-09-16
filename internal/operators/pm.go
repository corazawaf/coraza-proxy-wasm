// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3"

	"github.com/jcchavezs/coraza-wasm-filter/internal/ahocorasick"
)

type pm struct {
	m ahocorasick.Matcher
}

var _ coraza.RuleOperator = (*pm)(nil)

func (o *pm) Init(options coraza.RuleOperatorOptions) error {
	o.m = ahocorasick.NewMatcher(options.Arguments)
	return nil
}

func (o *pm) Evaluate(tx *coraza.Transaction, value string) bool {
	matches := o.m.Matches(value, 8)
	if tx.Capture {
		for i, c := range matches {
			tx.CaptureField(i, c)
		}
	}
	return len(matches) > 0
}
