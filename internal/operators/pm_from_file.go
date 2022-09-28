// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"

	"github.com/jcchavezs/coraza-wasm-filter/internal/ahocorasick"
)

type pmFromFile struct {
	m ahocorasick.Matcher
}

var _ rules.Operator = (*pmFromFile)(nil)

func (o *pmFromFile) Init(options rules.OperatorOptions) error {
	path := options.Arguments

	data, err := loadFromFile(path, options.Path, options.Root)
	if err != nil {
		return err
	}

	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := sc.Text()
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		if l[0] == '#' {
			continue
		}
		lines = append(lines, strings.ToLower(l))
	}

	o.m = ahocorasick.NewMatcher(lines)
	return nil
}

func (o *pmFromFile) Evaluate(tx rules.TransactionState, value string) bool {
	return pmEvaluate(o.m, tx, value)
}
