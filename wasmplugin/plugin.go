// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

type vmContext struct {
	// Embed the default VM context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultVMContext
}

func NewVMContext() types.VMContext {
	return &vmContext{}
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
	requestBodySize       int
	responseBodySize      int
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

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}
	// default value instantiated, OnHttpRequestHeaders does not terminate if IP/Port retrieve goes wrong
	var srcAddress, dstAddress AddressInfo

	srcAddressRaw, err := proxywasm.GetProperty([]string{"source", "address"})
	if err != nil {
		proxywasm.LogWarnf("failed to get source address: %v", err)
	} else {
		srcAddress.IP, err = parseAddress(srcAddressRaw)
		if err != nil {
			proxywasm.LogWarnf("failed to parse source address: %v", err)
		}
	}

	srcPortRaw, err := proxywasm.GetProperty([]string{"source", "port"})
	if err != nil {
		proxywasm.LogInfof("failed to get source port: %v", err)
	} else {
		srcAddress.port, err = parsePort(srcPortRaw)
		if err != nil {
			proxywasm.LogWarnf("failed to parse source port: %v", err)
		}
	}

	dstAddressRaw, err := proxywasm.GetProperty([]string{"destination", "address"})
	if err != nil {
		proxywasm.LogWarnf("failed to get destination address: %v", err)
	} else {
		dstAddress.IP, err = parseAddress(dstAddressRaw)
		if err != nil {
			proxywasm.LogWarnf("failed to parse destination address: %v", err)
		}
	}

	dstPortRaw, err := proxywasm.GetProperty([]string{"destination", "port"})
	if err != nil {
		proxywasm.LogInfof("failed to get destination port: %v", err)
	} else {
		dstAddress.port, err = parsePort(dstPortRaw)
		if err != nil {
			proxywasm.LogWarnf("failed to parse destination port: %v", err)
		}
	}
	tx.ProcessConnection(srcAddress.IP, srcAddress.port, dstAddress.IP, dstAddress.port)

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

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// Do not perform any action related to request body if SecRequestBodyAccess is set to false
	if !tx.RequestBodyAccessible() {
		proxywasm.LogDebug("skipping request body inspection, SecRequestBodyAccess is off.")
		return types.ActionContinue
	}

	ctx.requestBodySize += bodySize
	// Wait until we see the entire body. It has to be buffered in order to check that it is fully legit
	// before sending it upstream
	if !endOfStream {
		return types.ActionPause
	}

	if ctx.requestBodySize > 0 {
		body, err := proxywasm.GetHttpRequestBody(0, ctx.requestBodySize)
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

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

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

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// Do not perform any action related to response body if SecResponseBodyAccess is set to false
	if !tx.ResponseBodyAccessible() {
		proxywasm.LogDebug("skipping response body inspection, SecResponseBodyAccess is off.")
		return types.ActionContinue
	}

	ctx.responseBodySize += bodySize
	// Wait until we see the entire body. It has to be buffered in order to check that it is fully legit
	// before sending it downstream
	if !endOfStream {
		// TODO(M4tteoP): Update response body interruption logic after https://github.com/corazawaf/coraza-proxy-wasm/issues/26
		return types.ActionPause
	}

	if ctx.responseBodySize > 0 {
		body, err := proxywasm.GetHttpResponseBody(0, ctx.responseBodySize)
		if len(body) != ctx.responseBodySize {
			proxywasm.LogDebugf("warning: retrieved response body size different from the sum of all bodySizes. %d != %d", len(body), ctx.responseBodySize)
		}
		if err != nil {
			proxywasm.LogCriticalf("failed to get response body: %v", err)
			return types.ActionContinue
		}
		_, err = tx.ResponseBodyWriter().Write(body)
		if err != nil {
			proxywasm.LogCriticalf("failed to write response body: %v", err)
			return types.ActionContinue
		}
	}

	// We have already sent response headers, an unauthorized response can not be sent anymore,
	// but we can still drop the response to prevent leaking sensitive content.
	// The error will also be logged by Coraza.
	ctx.processedResponseBody = true
	interruption, err := tx.ProcessResponseBody()
	if err != nil {
		proxywasm.LogCriticalf("failed to process response body: %v", err)
		return types.ActionContinue
	}
	if interruption != nil {
		// TODO(M4tteoP): Update response body interruption logic after https://github.com/corazawaf/coraza-proxy-wasm/issues/26
		// Currently returns a body filled with null bytes that replaces the sensitive data potentially leaked
		err = proxywasm.ReplaceHttpResponseBody(bytes.Repeat([]byte("\x00"), ctx.responseBodySize))
		if err != nil {
			proxywasm.LogErrorf("failed to replace response body: %v", err)
			return types.ActionContinue
		}
		proxywasm.LogWarn("response body intervention occurred: body replaced")
		return types.ActionContinue
	}

	return types.ActionContinue
}

// Override types.DefaultHttpContext.
func (ctx *httpContext) OnHttpStreamDone() {
	defer logTime("OnHttpStreamDone", currentTime())
	tx := ctx.tx

	if !tx.IsRuleEngineOff() {
		// Responses without body won't call OnHttpResponseBody, but there are rules in the response body
		// phase that still need to be executed. If they haven't been executed yet, now is the time.
		if !ctx.processedResponseBody {
			ctx.processedResponseBody = true
			_, err := tx.ProcessResponseBody()
			if err != nil {
				proxywasm.LogCriticalf("failed to process response body: %v", err)
			}
		}
		// TODO(M4tteoP): update it once the discussion in https://github.com/corazawaf/coraza/issues/520 is settled
		ctx.tx.ProcessLogging()
	}

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
	switch error.Rule().Severity() {
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

type AddressInfo struct {
	IP   string
	port int
}

// Parsing address (e.g. "127.0.0.1:8080") to retrieve the IP
func parseAddress(rawAddress []byte) (string, error) {
	// Split address and port
	lastColonsPos := bytes.LastIndexByte(rawAddress, ':')
	if lastColonsPos == -1 {
		return "", errors.New("no match parsing address")
	}
	return string(rawAddress[:lastColonsPos]), nil
}

// Converts retrieved little-endian bytes into int
func parsePort(b []byte) (int, error) {
	// Port attribute ({"source", "port"}) is populated as uint64 (8 byte)
	// Ref: https://github.com/envoyproxy/envoy/blob/1b3da361279a54956f01abba830fc5d3a5421828/source/common/network/utility.cc#L201
	if len(b) < 4 {
		return 0, errors.New("port bytes not found")
	}
	// 0 < Port number <= 65535, therefore the retrieved value should never exceed 16 bits
	// and correctly fit int (at least 32 bits in size)
	unsignedInt := binary.LittleEndian.Uint32(b)
	if unsignedInt > math.MaxInt32 {
		return 0, errors.New("port convertion error")
	}
	return int(unsignedInt), nil
}
