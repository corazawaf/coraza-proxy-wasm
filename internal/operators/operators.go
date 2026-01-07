// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build wasilibs

package operators

import (
	wasilibs "github.com/corazawaf/coraza-wasilibs"
)

func Register() {
	wasilibs.RegisterRX()
	wasilibs.RegisterPM()
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()
}
