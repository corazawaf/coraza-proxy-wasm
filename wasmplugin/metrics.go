// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"fmt"
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

type wafMetrics struct {
	counters map[string]proxywasm.MetricCounter
}

func NewWAFMetrics() *wafMetrics {
	return &wafMetrics{
		counters: make(map[string]proxywasm.MetricCounter),
	}
}

func (m *wafMetrics) incrementCounter(fqn string) {
	// TODO(jcchavezs): figure out if we are OK with dynamic creation of metrics
	// or we generate the metrics on before hand.
	counter, ok := m.counters[fqn]
	if !ok {
		counter = proxywasm.DefineCounterMetric(fqn)
		m.counters[fqn] = counter
	}
	counter.Increment(1)
}

func (m *wafMetrics) CountTX() {
	// This metric is processed as: waf_filter_tx_total
	m.incrementCounter("waf_filter.tx.total")
}

func (m *wafMetrics) CountTXInterruption(phase string, ruleID int, metricLabelsKV []string) {
	// This metric is processed as: waf_filter_tx_interruption{phase="http_request_body",rule_id="100",identifier="foo"}.
	// The extraction rule is defined in envoy.yaml as a bootstrap configuration.
	// See https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/metrics/v3/stats.proto#config-metrics-v3-statsconfig.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("waf_filter.tx.interruptions_ruleid=%d_phase=%s", ruleID, phase))

	for i := 0; i < len(metricLabelsKV); i += 2 {
		sb.WriteString(fmt.Sprintf("_%s=%s", metricLabelsKV[i], metricLabelsKV[i+1]))
	}

	fqn := sb.String()
	m.incrementCounter(fqn)
}

func (m *wafMetrics) CountTXMatchedRules(phase string, ruleID int, transactionID string, metricLabelsKV []string, flagTransactionID bool) {
	// Using the same logic as Count TXInterruption, but with this metric we want to:
	// - record the number of times a rule was triggered in a specific phase of the specified transaction
	// - record the phase where the rule was triggered
	// - record the rule ID
	// - record the transaction ID of matched rule. This is a unique identifier for the transaction.
	// - record the labels that were used to identify the rule.
	// This is metric is processed as:
	// waf_filter_tx_matchedrules{phase="http_request_body",rule_id="100",transaction_id="SJNBEaBHutzVixMcVRi",identifier="global"}.
	var sb strings.Builder

	if flagTransactionID {
		sb.WriteString(fmt.Sprintf("waf_filter.tx.matchedrules_ruleid=%d_transactionid=%s_phase=%s", ruleID, transactionID, phase))
	} else {
		sb.WriteString(fmt.Sprintf("waf_filter.tx.matchedrules_ruleid=%d_phase=%s", ruleID, phase))
	}

	for i := 0; i < len(metricLabelsKV); i += 2 {
		sb.WriteString(fmt.Sprintf("_%s=%s", metricLabelsKV[i], metricLabelsKV[i+1]))
	}

	fqn := sb.String()
	m.incrementCounter(fqn)
}
