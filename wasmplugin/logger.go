// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"io"

	"github.com/corazawaf/coraza/v3/debuglogger"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

type logger struct {
	debuglogger.Logger
}

var _ debuglogger.Logger = logger{}

var logPrinterFactory = func(io.Writer) debuglogger.Printer {
	return func(lvl debuglogger.LogLevel, message, fields string) {
		switch lvl {
		case debuglogger.LogLevelTrace:
			proxywasm.LogTracef("%s %s", message, fields)
		case debuglogger.LogLevelDebug:
			proxywasm.LogDebugf("%s %s", message, fields)
		case debuglogger.LogLevelInfo:
			proxywasm.LogInfof("%s %s", message, fields)
		case debuglogger.LogLevelWarn:
			proxywasm.LogWarnf("%s %s", message, fields)
		case debuglogger.LogLevelError:
			proxywasm.LogErrorf("%s %s", message, fields)
		default:
		}
	}
}

func DefaultLogger() debuglogger.Logger {
	return logger{
		debuglogger.DefaultWithPrinterFactory(logPrinterFactory),
	}
}

func (l logger) WithLevel(lvl debuglogger.LogLevel) debuglogger.Logger {
	return logger{l.Logger.WithLevel(lvl)}
}

func (l logger) WithOutput(_ io.Writer) debuglogger.Logger {
	proxywasm.LogWarn("ignoring SecDebugLog directive, debug logs are always routed to proxy logs")
	return l
}
