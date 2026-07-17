// Copyright The OWASP Coraza contributors
// Modifications Copyright (c) 2026 Tigera, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"

	"github.com/corazawaf/coraza-proxy-wasm/internal/auditlog"
	"github.com/corazawaf/coraza-proxy-wasm/internal/operators"
	"github.com/corazawaf/coraza-proxy-wasm/wasmplugin"
)

// Registration moved from main() to init() with the TinyGo 0.34 -> 0.39
// migration. TinyGo 0.35 made WASI modules call proc_exit after main() returns
// (tinygo#4721), which kills a long-lived proxy-wasm module at _start with
// Envoy's "restricted_callback". Building with -buildmode=wasi-legacy (see
// magefiles Build()) restores persist-after-main, and doing the setup in init()
// keeps it running before main() is entered.
func init() {
	operators.Register()
	auditlog.RegisterProxyWasmSerialWriter()
	proxywasm.SetVMContext(wasmplugin.NewVMContext())
}

func main() {}
