// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/coraza-wasm-filter/internal/injection"
)

type detectSQLi struct {
}

var _ coraza.RuleOperator = (*detectSQLi)(nil)

func (o *detectSQLi) Init(options coraza.RuleOperatorOptions) error { return nil }

func (o *detectSQLi) Evaluate(tx *coraza.Transaction, value string) bool {
	res, fp := injection.IsSQLi(value)
	if !res {
		return false
	}
	if tx.Capture {
		tx.CaptureField(0, string(fp))
	}
	return true
}
