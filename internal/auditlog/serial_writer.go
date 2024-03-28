// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"io"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// Coraza does not come with a built-in audit log writer for Wasm
// See https://github.com/corazawaf/coraza/blob/main/internal/auditlog/init_tinygo.go
// This function overrides the default "Serial" audit log writer in order to print audit logs
// to the proxy-wasm log as info messages.
func RegisterWasmSerialWriter() {
	plugins.RegisterAuditLogWriter("serialNotUsed", func() plugintypes.AuditLogWriter {
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

	proxywasm.LogInfo(string(bts))
	return nil
}

func (s *wasmSerial) Close() error { return nil }
