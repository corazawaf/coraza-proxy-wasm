// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/rules"

	"github.com/jcchavezs/coraza-wasm-filter/internal/re2"
)

type rx struct {
	re    re2.RegExp
	debug bool
}

var _ rules.Operator = (*rx)(nil)

func (o *rx) Init(options rules.OperatorOptions) error {
	data := options.Arguments
	// fmt.Println(data)
	if data == `(?:\$(?:\((?:\(.*\)|.*)\)|\{.*})|\/\w*\[!?.+\]|[<>]\(.*\))` {
		o.debug = true
		fmt.Println("enabling rx debug!")
	}

	re, err := re2.Compile(data)
	o.re = re
	return err
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
