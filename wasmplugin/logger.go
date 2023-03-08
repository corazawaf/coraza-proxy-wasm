// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"io"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

type logger struct {
	debuglog.Logger
}

var _ debuglog.Logger = logger{}

var logPrinterFactory = func(io.Writer) debuglog.Printer {
	return func(lvl debuglog.LogLevel, message, fields string) {
		switch lvl {
		case debuglog.LogLevelTrace:
			proxywasm.LogTracef("%s %s", message, fields)
		case debuglog.LogLevelDebug:
			proxywasm.LogDebugf("%s %s", message, fields)
		case debuglog.LogLevelInfo:
			proxywasm.LogInfof("%s %s", message, fields)
		case debuglog.LogLevelWarn:
			proxywasm.LogWarnf("%s %s", message, fields)
		case debuglog.LogLevelError:
			proxywasm.LogErrorf("%s %s", message, fields)
		default:
		}
	}
}

func DefaultLogger() debuglog.Logger {
	return logger{
		debuglog.DefaultWithPrinterFactory(logPrinterFactory),
	}
}

func (l logger) WithLevel(lvl debuglog.LogLevel) debuglog.Logger {
	return logger{l.Logger.WithLevel(lvl)}
}

func (l logger) WithOutput(_ io.Writer) debuglog.Logger {
	proxywasm.LogWarn("ignoring SecDebugLog directive, debug logs are always routed to proxy logs")
	return l
}
