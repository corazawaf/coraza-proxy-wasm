// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/seclang"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	// Embed the default VM context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultVMContext
}

// Override types.DefaultVMContext.
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &corazaPlugin{}
}

type corazaPlugin struct {
	// Embed the default plugin context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultPluginContext

	waf *coraza.Waf
}

// pluginConfiguration is a type to represent an example configuration for this wasm plugin.
type pluginConfiguration struct {
	rules string
}

// Override types.DefaultPluginContext.
func (ctx *corazaPlugin) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil && err != types.ErrorStatusNotFound {
		proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	config, err := parsePluginConfiguration(data)
	if err != nil {
		proxywasm.LogCriticalf("error parsing plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	// First we initialize our waf and our seclang parser
	waf := coraza.NewWaf()
	waf.SetErrorLogCb(logError)

	// TinyGo compilation will prevent buffering request body to files anyways, so this is
	// effectively no-op but make clear our expectations.
	// TODO(anuraaga): Make this configurable in plugin configuration.
	waf.RequestBodyLimit = waf.RequestBodyInMemoryLimit

	parser, err := seclang.NewParser(waf)
	if err != nil {
		proxywasm.LogCriticalf("failed to create seclang parser: %v", err)
		return types.OnPluginStartStatusFailed
	}

	err = parser.FromString(config.rules)
	if err != nil {
		proxywasm.LogCriticalf("failed to parse rules: %v", err)
		return types.OnPluginStartStatusFailed
	}

	ctx.waf = waf

	return types.OnPluginStartStatusOK
}

func parsePluginConfiguration(data []byte) (pluginConfiguration, error) {
	if len(data) == 0 {
		return pluginConfiguration{}, nil
	}
	config := &pluginConfiguration{}
	if !gjson.ValidBytes(data) {
		return pluginConfiguration{}, fmt.Errorf("invalid json: %q", string(data))
	}

	jsonData := gjson.ParseBytes(data)
	rules := jsonData.Get("rules")
	if !rules.Exists() {
		return pluginConfiguration{}, fmt.Errorf("missing rules: %q", string(data))
	}
	config.rules = rules.String()

	return *config, nil
}

// Override types.DefaultPluginContext.
func (ctx *corazaPlugin) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{contextID: contextID, tx: ctx.waf.NewTransaction(context.Background())}
}

type httpContext struct {
	// Embed the default http context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultHttpContext
	contextID uint32
	tx        *coraza.Transaction
}

// Override types.DefaultHttpContext.
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	tx := ctx.tx

	// TODO(anuraaga): Do these work with HTTP/1?
	path, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		proxywasm.LogCriticalf("failed to get :path: %v", err)
		return types.ActionContinue
	}

	method, err := proxywasm.GetHttpRequestHeader(":method")
	if err != nil {
		proxywasm.LogCriticalf("failed to get :method: %v", err)
		return types.ActionContinue
	}

	tx.ProcessURI(path, method, "2.0") // TODO use the right HTTP version

	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		proxywasm.LogCriticalf("failed to get request headers: %v", err)
		return types.ActionContinue
	}

	for _, h := range hs {
		tx.AddRequestHeader(h[0], h[1])
	}

	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		ctx.handleInterruption(interruption)
		return types.ActionContinue
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	tx := ctx.tx

	if bodySize > 0 {
		body, err := proxywasm.GetHttpRequestBody(0, bodySize)
		if err != nil {
			proxywasm.LogCriticalf("failed to get request body: %v", err)
			return types.ActionContinue
		}

		_, err = tx.RequestBodyBuffer.Write(body)
		if err != nil {
			proxywasm.LogCriticalf("failed to read request body: %v", err)
			return types.ActionContinue
		}
	}

	if !endOfStream {
		return types.ActionContinue
	}

	interruption, err := tx.ProcessRequestBody()
	if err != nil {
		proxywasm.LogCriticalf("failed to process request body: %v", err)
		return types.ActionContinue
	}
	if interruption != nil {
		ctx.handleInterruption(interruption)
		return types.ActionContinue
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {
	tx := ctx.tx

	status, err := proxywasm.GetHttpResponseHeader(":status")
	if err != nil {
		proxywasm.LogCriticalf("failed to get :status: %v", err)
		return types.ActionContinue
	}
	code, err := strconv.Atoi(status)
	if err != nil {
		code = 0
	}

	hs, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		proxywasm.LogCriticalf("failed to get response headers: %v", err)
		return types.ActionContinue
	}

	for _, h := range hs {
		tx.AddResponseHeader(h[0], h[1])
	}

	interruption := tx.ProcessResponseHeaders(code, "2.0")
	if interruption != nil {
		ctx.handleInterruption(interruption)
		return types.ActionContinue
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpResponseBody(bodySize int, endOfStream bool) types.Action {
	tx := ctx.tx

	if bodySize > 0 {
		body, err := proxywasm.GetHttpResponseBody(0, bodySize)
		if err != nil {
			proxywasm.LogCriticalf("failed to get response body: %v", err)
			return types.ActionContinue
		}

		_, err = tx.ResponseBodyBuffer.Write(body)
		if err != nil {
			proxywasm.LogCriticalf("failed to read response body: %v", err)
			return types.ActionContinue
		}
	}

	if !endOfStream {
		return types.ActionContinue
	}

	interruption, err := tx.ProcessResponseBody()
	if err != nil {
		proxywasm.LogCriticalf("failed to process response body: %v", err)
		return types.ActionContinue
	}
	if interruption != nil {
		ctx.handleInterruption(interruption)
		return types.ActionContinue
	}

	return types.ActionContinue
}

// Override types.DefaultHttpContext.
func (ctx *httpContext) OnHttpStreamDone() {
	ctx.tx.ProcessLogging()
	_ = ctx.tx.Clean()
	proxywasm.LogInfof("%d finished", ctx.contextID)
}

func (ctx *httpContext) handleInterruption(interruption *ctypes.Interruption) {
	proxywasm.LogInfof("%d interrupted, action %q", ctx.contextID, interruption.Action)
	statusCode := interruption.Status
	if statusCode == 0 {
		statusCode = 403
	}

	if err := proxywasm.SendHttpResponse(uint32(statusCode), nil, nil, -1); err != nil {
		panic(err)
	}
}

func logError(error ctypes.MatchedRule) {
	msg := error.ErrorLog(0)
	switch error.Rule.Severity {
	case ctypes.RuleSeverityEmergency:
		proxywasm.LogCritical(msg)
	case ctypes.RuleSeverityAlert:
		proxywasm.LogCritical(msg)
	case ctypes.RuleSeverityCritical:
		proxywasm.LogCritical(msg)
	case ctypes.RuleSeverityError:
		proxywasm.LogError(msg)
	case ctypes.RuleSeverityWarning:
		proxywasm.LogWarn(msg)
	case ctypes.RuleSeverityNotice:
		proxywasm.LogInfo(msg)
	case ctypes.RuleSeverityInfo:
		proxywasm.LogInfo(msg)
	case ctypes.RuleSeverityDebug:
		proxywasm.LogDebug(msg)
	}
}
