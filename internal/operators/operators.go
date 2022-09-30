// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3/operators"
	"github.com/corazawaf/coraza/v3/rules"
)

func Register() {
	operators.Register("detectSQLi", func() rules.Operator { return &detectSQLi{} })
	operators.Register("detectXSS", func() rules.Operator { return &detectXSS{} })
	operators.Register("rx", func() rules.Operator { return &rx{} })
	operators.Register("pm", func() rules.Operator { return &pm{} })
	operators.Register("pmFromFile", func() rules.Operator { return &pmFromFile{} })
}
