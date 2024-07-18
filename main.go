// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"

	"github.com/corazawaf/coraza-proxy-wasm/internal/auditlog"
	"github.com/corazawaf/coraza-proxy-wasm/internal/operators"
	"github.com/corazawaf/coraza-proxy-wasm/wasmplugin"
)

func main() {
	operators.Register()
	auditlog.RegisterProxyWasmSerialWriter()
	proxywasm.SetVMContext(wasmplugin.NewVMContext())
}
