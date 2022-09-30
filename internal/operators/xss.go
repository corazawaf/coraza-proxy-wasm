// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3/rules"

	"github.com/jcchavezs/coraza-wasm-filter/internal/injection"
)

type detectXSS struct {
}

var _ rules.Operator = (*detectXSS)(nil)

func (o *detectXSS) Init(options rules.OperatorOptions) error { return nil }

func (o *detectXSS) Evaluate(tx rules.TransactionState, value string) bool {
	return injection.IsXSS(value)
}
