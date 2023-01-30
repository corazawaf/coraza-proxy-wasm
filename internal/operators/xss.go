// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/wasilibs/go-libinjection"
)

type detectXSS struct{}

var _ rules.Operator = (*detectXSS)(nil)

func newDetectXSS(rules.OperatorOptions) (rules.Operator, error) {
	return &detectXSS{}, nil
}

func (o *detectXSS) Evaluate(tx rules.TransactionState, value string) bool {
	return libinjection.IsXSS(value)
}
