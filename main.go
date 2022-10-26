// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"embed"
	"io/fs"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"

	"github.com/corazawaf/coraza-proxy-wasm/internal/bodyprocessors"
	"github.com/corazawaf/coraza-proxy-wasm/internal/operators"
)

//go:embed rules
var crs embed.FS

func main() {
	bodyprocessors.Register()
	operators.Register()
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

	waf coraza.WAF

	metrics *wafMetrics
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

	root, _ := fs.Sub(crs, "rules")

	// First we initialize our waf and our seclang parser
	conf := coraza.NewWAFConfig().
		WithErrorLogger(logError).
		WithDebugLogger(&debugLogger{}).
		WithRequestBodyAccess(coraza.NewRequestBodyConfig().
			WithLimit(1024 * 1024 * 1024).
			// TinyGo compilation will prevent buffering request body to files anyways.
			// TODO(anuraaga): Make this configurable in plugin configuration.
			WithInMemoryLimit(1024 * 1024 * 1024)).
		WithRootFS(root)

	waf, err := coraza.NewWAF(conf.WithDirectives(strings.Join(config.rules, "\n")))
	if err != nil {
		proxywasm.LogCriticalf("failed to parse rules: %v", err)
		return types.OnPluginStartStatusFailed
	}

	ctx.waf = waf

	ctx.metrics = NewWAFMetrics()

	return types.OnPluginStartStatusOK
}

// Override types.DefaultPluginContext.
func (ctx *corazaPlugin) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{
		contextID: contextID,
		tx:        ctx.waf.NewTransaction(),
		// TODO(jcchavezs): figure out how/when enable/disable metrics
		metrics: ctx.metrics,
	}
}

type httpContext struct {
	// Embed the default http context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultHttpContext
	contextID             uint32
	tx                    ctypes.Transaction
	httpProtocol          string
	processedRequestBody  bool
	processedResponseBody bool
	metrics               *wafMetrics
}

// Override types.DefaultHttpContext.
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	defer logTime("OnHttpRequestHeaders", currentTime())
	ctx.metrics.CountTX()
	tx := ctx.tx

	// This currently relies on Envoy's behavior of mapping all requests to HTTP/2 semantics
	// and its request properties, but they may not be true of other proxies implementing
	// proxy-wasm.

	// Note the pseudo-header :path includes the query.
	// See https://httpwg.org/specs/rfc9113.html#rfc.section.8.3.1
	uri, err := proxywasm.GetHttpRequestHeader(":path")
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

	tx.ProcessURI(uri, method, ctx.httpProtocol)

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
		return ctx.handleInterruption("http_request_headers", interruption)
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	defer logTime("OnHttpRequestBody", currentTime())
	tx := ctx.tx

	if bodySize > 0 {
		body, err := proxywasm.GetHttpRequestBody(0, bodySize)
		if err != nil {
			proxywasm.LogCriticalf("failed to get request body: %v", err)
			return types.ActionContinue
		}

		_, err = tx.RequestBodyWriter().Write(body)
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
		return ctx.handleInterruption("http_request_body", interruption)
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {
	defer logTime("OnHttpResponseHeaders", currentTime())
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
			return ctx.handleInterruption("http_response_headers", interruption)
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
		return ctx.handleInterruption("http_response_headers", interruption)
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpResponseBody(bodySize int, endOfStream bool) types.Action {
	defer logTime("OnHttpResponseBody", currentTime())
	tx := ctx.tx

	if bodySize > 0 {
		body, err := proxywasm.GetHttpResponseBody(0, bodySize)
		if err != nil {
			proxywasm.LogCriticalf("failed to get response body: %v", err)
			return types.ActionContinue
		}
		_, err = tx.ResponseBodyWriter().Write(body)
		if err != nil {
			proxywasm.LogCriticalf("failed to read response body: %v", err)
			return types.ActionContinue
		}
	}

	// Response  body has to be buffered in order to check that it is fully legit
	if !endOfStream {
		// TODO(M4tteoP): Address response body interruption logic after https://github.com/corazawaf/coraza-proxy-wasm/issues/26
		// return types.ActionPause
		return types.ActionContinue
	}

	// We have already sent response headers, an unauthorized response can not be sent anymore,
	// but we can still drop the response to prevent leaking sensitive content
	// The error will also be logged by Coraza.
	ctx.processedResponseBody = true
	interruption, err := tx.ProcessResponseBody()
	if err != nil {
		proxywasm.LogCriticalf("failed to process response body: %v", err)
		return types.ActionContinue
	}
	if interruption != nil {
		// TODO(M4tteoP): Address response body interruption logic after https://github.com/corazawaf/coraza-proxy-wasm/issues/26
		return types.ActionContinue
	}

	return types.ActionContinue
}

// Override types.DefaultHttpContext.
func (ctx *httpContext) OnHttpStreamDone() {
	defer logTime("OnHttpStreamDone", currentTime())
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
	_ = ctx.tx.Close()
	proxywasm.LogInfof("%d finished", ctx.contextID)
	logMemStats()
}

func (ctx *httpContext) handleInterruption(phase string, interruption *ctypes.Interruption) types.Action {
	ctx.metrics.CountTXInterruption(phase, interruption.RuleID)

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
