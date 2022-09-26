// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/operators"
)

func Register() {
	operators.Register("detectSQLi", func() coraza.RuleOperator { return &detectSQLi{} })
	operators.Register("detectXSS", func() coraza.RuleOperator { return &detectXSS{} })
	operators.Register("rx", func() coraza.RuleOperator { return &rx{} })
	operators.Register("pm", func() coraza.RuleOperator { return &pm{} })
	operators.Register("pmFromFile", func() coraza.RuleOperator { return &pmFromFile{} })
}
