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
	return o.re.FindStringSubmatch8(value, func(i int, match string) {
		if tx.Capture {
			tx.CaptureField(i, match)
		}
	})
}
