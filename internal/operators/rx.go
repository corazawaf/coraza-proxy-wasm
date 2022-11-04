// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/rules"

	"github.com/corazawaf/coraza-proxy-wasm/internal/re2"
)

type rx struct {
	re    re2.RegExp
	debug bool
}

var _ rules.Operator = (*rx)(nil)

func newRX(options rules.OperatorOptions) (rules.Operator, error) {
	o := &rx{}
	data := options.Arguments

	if data == `(?:\$(?:\((?:\(.*\)|.*)\)|\{.*})|\/\w*\[!?.+\]|[<>]\(.*\))` {
		o.debug = true
		fmt.Println("enabling rx debug!")
	}

	re, err := re2.Compile(data)
	if err != nil {
		return nil, err
	}

	o.re = re
	return o, err
}

func (o *rx) Evaluate(tx rules.TransactionState, value string) bool {
	res := o.re.FindStringSubmatch8(value, func(i int, match string) {
		tx.CaptureField(i, match)
	})
	if o.debug {
		fmt.Println(res)
	}
	return res
}
