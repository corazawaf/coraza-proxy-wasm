// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/wasilibs/go-libinjection"
)

type detectSQLi struct{}

var _ rules.Operator = (*detectSQLi)(nil)

func newDetectSQLi(rules.OperatorOptions) (rules.Operator, error) {
	return &detectSQLi{}, nil
}

func (o *detectSQLi) Evaluate(tx rules.TransactionState, value string) bool {
	res, fp := libinjection.IsSQLi(value)
	if !res {
		return false
	}
	tx.CaptureField(0, string(fp))
	return true
}
