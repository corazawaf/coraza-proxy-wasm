// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strconv"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/seclang"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

//go:embed custom_rules
var crs embed.FS

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
	rules      string
	includeCRS bool
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
	waf.Logger = &debugLogger{}

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

	if config.includeCRS {
		err = fs.WalkDir(crs, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			f, _ := crs.ReadFile(path)
			if err := parser.FromString(string(f)); err != nil {
				return fmt.Errorf("%s: %v", path, err)
			}

			return nil
		})
		if err != nil {
			proxywasm.LogCriticalf("failed to parse core rule set: %v", err)
			return types.OnPluginStartStatusFailed
		}
	}

	ctx.waf = waf

	return types.OnPluginStartStatusOK
}

func parsePluginConfiguration(data []byte) (pluginConfiguration, error) {
	config := pluginConfiguration{
		includeCRS: true,
	}
	if len(data) == 0 {
		return config, nil
	}
	if !gjson.ValidBytes(data) {
		return pluginConfiguration{}, fmt.Errorf("invalid json: %q", string(data))
	}

	jsonData := gjson.ParseBytes(data)
	rules := jsonData.Get("rules")
	if rules.Exists() {
		config.rules = rules.String()
	}

	includeCRS := jsonData.Get("include_core_rule_set")
	if includeCRS.Exists() && !includeCRS.Bool() {
		config.includeCRS = false
	}

	return config, nil
}

// Override types.DefaultPluginContext.
func (ctx *corazaPlugin) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{contextID: contextID, tx: ctx.waf.NewTransaction(context.Background())}
}

type httpContext struct {
	// Embed the default http context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultHttpContext
	contextID             uint32
	tx                    *coraza.Transaction
	httpProtocol          string
	processedRequestBody  bool
	processedResponseBody bool
}

// Override types.DefaultHttpContext.
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	tx := ctx.tx

	// This currently relies on Envoy's behavior of mapping all requests to HTTP/2 semantics
	// and its request properties, but they may not be true of other proxies implementing
	// proxy-wasm.

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

	protocol, err := proxywasm.GetProperty([]string{"request", "protocol"})
	if err != nil {
		// TODO(anuraaga): HTTP protocol is commonly required in WAF rules, we should probably
		// fail fast here, but proxytest does not support properties yet.
		protocol = []byte("HTTP/2.0")
	}

	ctx.httpProtocol = string(protocol)

	tx.ProcessURI(path, method, ctx.httpProtocol)

	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		proxywasm.LogCriticalf("failed to get request headers: %v", err)
		return types.ActionContinue
	}

	for _, h := range hs {
		tx.AddRequestHeader(h[0], h[1])
	}

	// CRS rules tend to expect Host even with HTTP/2
	authority, err := proxywasm.GetHttpRequestHeader(":authority")
	if err == nil {
		tx.AddRequestHeader("Host", authority)
	}

	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		return ctx.handleInterruption(interruption)
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

	ctx.processedRequestBody = true
	interruption, err := tx.ProcessRequestBody()
	if err != nil {
		proxywasm.LogCriticalf("failed to process request body: %v", err)
		return types.ActionContinue
	}
	if interruption != nil {
		return ctx.handleInterruption(interruption)
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {
	tx := ctx.tx

	// Requests without body won't call OnHttpRequestBody, but there are rules in the request body
	// phase that still need to be executed. If they haven't been executed yet, now is the time.
	if !ctx.processedRequestBody {
		ctx.processedRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			proxywasm.LogCriticalf("failed to process request body: %v", err)
			return types.ActionContinue
		}
		if interruption != nil {
			return ctx.handleInterruption(interruption)
		}
	}

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

	interruption := tx.ProcessResponseHeaders(code, ctx.httpProtocol)
	if interruption != nil {
		return ctx.handleInterruption(interruption)
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

	// We have already sent response headers so cannot now send an unauthorized response.
	// The error will have been logged by Coraza though.
	ctx.processedResponseBody = true
	_, err := tx.ProcessResponseBody()
	if err != nil {
		proxywasm.LogCriticalf("failed to process response body: %v", err)
		return types.ActionContinue
	}

	return types.ActionContinue
}

// Override types.DefaultHttpContext.
func (ctx *httpContext) OnHttpStreamDone() {
	tx := ctx.tx

	// Responses without body won't call OnHttpResponseBody, but there are rules in the response body
	// phase that still need to be executed. If they haven't been executed yet, now is the time.
	if !ctx.processedResponseBody {
		ctx.processedResponseBody = true
		_, err := tx.ProcessResponseBody()
		if err != nil {
			proxywasm.LogCriticalf("failed to process response body: %v", err)
		}
	}

	ctx.tx.ProcessLogging()
	_ = ctx.tx.Clean()
	proxywasm.LogInfof("%d finished", ctx.contextID)
}

func (ctx *httpContext) handleInterruption(interruption *ctypes.Interruption) types.Action {
	proxywasm.LogInfof("%d interrupted, action %q", ctx.contextID, interruption.Action)
	statusCode := interruption.Status
	if statusCode == 0 {
		statusCode = 403
	}

	if err := proxywasm.SendHttpResponse(uint32(statusCode), nil, nil, -1); err != nil {
		panic(err)
	}

	return types.ActionPause
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
