// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3"

	"github.com/jcchavezs/coraza-wasm-filter/internal/injection"
)

type detectXSS struct {
}

var _ coraza.RuleOperator = (*detectXSS)(nil)

func (o *detectXSS) Init(options coraza.RuleOperatorOptions) error { return nil }

func (o *detectXSS) Evaluate(tx *coraza.Transaction, value string) bool {
	return injection.IsXSS(value)
}
