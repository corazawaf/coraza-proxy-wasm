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

func (m *wafMetrics) CountTXInterruption(phase string, ruleID int, metricLabels map[string]string) {
	// This metric is processed as: waf_filter_tx_interruption{phase="http_request_body",rule_id="100",identifier="foo"}.
	// The extraction rule is defined in envoy.yaml as a bootstrap configuration.
	// See https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/metrics/v3/stats.proto#config-metrics-v3-statsconfig.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("waf_filter.tx.interruptions_ruleid=%d_phase=%s", ruleID, phase))

	for key, value := range metricLabels {
		sb.WriteString(fmt.Sprintf("_%s=%s", key, value))
	}

	fqn := sb.String()
	m.incrementCounter(fqn)
}
