package wasmplugin

import (
	"fmt"
	"sync"

	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// Transaction context to store against a transaction ID
type TxnContext struct {
	envoyRequestId string
}

// Logger that includes context from the request in the audit logs and owns the final formatting
type ContextualAuditLogger struct {
	IncludeRequestContext bool
	txnContextMap         map[string]*TxnContext
	lock                  sync.Mutex
}

// Get the global audit logger that can be used across all requests
func NewAppAuditLogger(includeRequestContext bool) *ContextualAuditLogger {
	return &ContextualAuditLogger{
		txnContextMap:         make(map[string]*TxnContext),
		IncludeRequestContext: includeRequestContext,
	}
}

// Register a transaction with the logger
func (cal *ContextualAuditLogger) Register(txnId string, ctx *TxnContext) {
	cal.lock.Lock()
	defer cal.lock.Unlock()

	cal.txnContextMap[txnId] = ctx
}

// Remove the transaction information from the context map
func (cal *ContextualAuditLogger) Unregister(txnId string) {
	cal.lock.Lock()
	defer cal.lock.Unlock()

	delete(cal.txnContextMap, txnId)
}

// Emit log on the given rule and add the txn context if available
func (cal *ContextualAuditLogger) AuditLog(rule ctypes.MatchedRule) {
	cal.lock.Lock()
	defer cal.lock.Unlock()

	txnId := rule.TransactionID()

	logPrefix := ""
	if ctx, ok := cal.txnContextMap[txnId]; ok {
		if cal.IncludeRequestContext {
			// If we have context, add it to the log
			logPrefix = fmt.Sprintf("[request-id %q] ", ctx.envoyRequestId)
		}
	}

	logError(rule, logPrefix)
}

func logError(error ctypes.MatchedRule, logPrefix string) {
	msg := logPrefix + error.ErrorLog()
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

const (
	// This is the standard Envoy header for request IDs
	envoyRequestIdHeader = "x-request-id"
)

// A convenience method to register the request information with the audit logger if available
// on the request (else ignores). Must be called in the request context.
func registerRequestContextWithLogger(auditLogger *ContextualAuditLogger, txnId string) {
	if id, err := proxywasm.GetHttpRequestHeader(envoyRequestIdHeader); err == nil {
		auditLogger.Register(txnId, &TxnContext{
			envoyRequestId: id,
		})
	}
}

// Remove context for the given transaction ID
func removeRequestContextFromLogger(auditLogger *ContextualAuditLogger, txnId string) {
	auditLogger.Unregister(txnId)
}
