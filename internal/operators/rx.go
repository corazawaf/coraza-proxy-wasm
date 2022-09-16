// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/coraza-wasm-filter/internal/re2"
)

type rx struct {
	re re2.RegExp
}

var _ coraza.RuleOperator = (*rx)(nil)

func (o *rx) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	re, err := re2.Compile(data)
	o.re = re
	return err
}

func (o *rx) Evaluate(tx *coraza.Transaction, value string) bool {
	matches := o.re.FindStringSubmatch(value, 8)
	if len(matches) == 0 {
		return false
	}

	if tx.Capture {
		for i, c := range matches {
			tx.CaptureField(i, c)
		}
	}

	return true
}
