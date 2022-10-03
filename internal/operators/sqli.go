// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3/rules"

	"github.com/corazawaf/coraza-proxy-wasm/internal/injection"
)

type detectSQLi struct {
}

var _ rules.Operator = (*detectSQLi)(nil)

func (o *detectSQLi) Init(options rules.OperatorOptions) error { return nil }

func (o *detectSQLi) Evaluate(tx rules.TransactionState, value string) bool {
	res, fp := injection.IsSQLi(value)
	if !res {
		return false
	}
	tx.CaptureField(0, string(fp))
	return true
}
