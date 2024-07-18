// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"io"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// RegisterProxyWasmSerialWriter overrides the default "Serial" audit log writer (see https://github.com/corazawaf/coraza/blob/main/internal/auditlog/init_tinygo.go)
// in order to print audit logs to the proxy-wasm log as info messages with a prefix to differentiate them from other logs.
func RegisterProxyWasmSerialWriter() {
	plugins.RegisterAuditLogWriter("serial", func() plugintypes.AuditLogWriter {
		return &wasmSerial{}
	})
}

type wasmSerial struct {
	io.Closer
	formatter plugintypes.AuditLogFormatter
}

func (s *wasmSerial) Init(cfg plugintypes.AuditLogConfig) error {
	s.formatter = cfg.Formatter
	return nil
}

func (s *wasmSerial) Write(al plugintypes.AuditLog) error {
	if s.formatter == nil {
		return nil
	}

	bts, err := s.formatter.Format(al)
	if err != nil {
		return err
	}

	if len(bts) == 0 {
		return nil
	}
	// Print the audit log to the proxy-wasm log as an info message adding an "AuditLog:" prefix.
	proxywasm.LogInfo("AuditLog:" + string(bts))
	return nil
}

func (s *wasmSerial) Close() error { return nil }
