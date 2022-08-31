// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"

	"github.com/corazawaf/coraza/v3"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

type debugLogger struct {
	level coraza.LogLevel
}

func (l *debugLogger) Info(message string, args ...interface{}) {
	if l.level >= coraza.LogLevelInfo {
		proxywasm.LogInfof(message, args...)
	}
}

func (l *debugLogger) Warn(message string, args ...interface{}) {
	if l.level >= coraza.LogLevelWarn {
		proxywasm.LogWarnf(message, args...)
	}
}

func (l *debugLogger) Error(message string, args ...interface{}) {
	if l.level >= coraza.LogLevelError {
		proxywasm.LogErrorf(message, args...)
	}
}

func (l *debugLogger) Debug(message string, args ...interface{}) {
	if l.level >= coraza.LogLevelDebug {
		proxywasm.LogDebugf(message, args...)
	}
}

func (l *debugLogger) Trace(message string, args ...interface{}) {
	if l.level >= coraza.LogLevelTrace {
		proxywasm.LogTracef(message, args...)
	}
}

func (l *debugLogger) SetLevel(level coraza.LogLevel) {
	l.level = level
}

func (l *debugLogger) SetOutput(w io.Writer) {
	proxywasm.LogWarn("ignoring SecDebugLog directive, debug logs are always routed to proxy logs")
}
