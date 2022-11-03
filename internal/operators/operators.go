// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3/operators"
)

func Register() {

	operators.Register("detectSQLi", newDetectSQLi)
	operators.Register("detectXSS", newDetectXSS)
	operators.Register("rx", newRX)
	operators.Register("pm", newPM)
	operators.Register("pmFromFile", newPMFromFile)
}
