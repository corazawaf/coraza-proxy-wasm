// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

type wafMetrics struct {
	counters   map[string]proxywasm.MetricCounter
	histograms map[string]proxywasm.MetricHistogram
}

var actions = map[types.Action]string{
	types.ActionContinue: "continue",
	types.ActionPause:    "pause",
}

func (m *wafMetrics) CountAction(phase string, a types.Action, tagsKV ...string) {
	// This metric is processed as: waf_filter.action_count{action="continue",phase="on_http_request_body",rule_id="100"}.
	// The extraction rule is defined in envoy.yaml as a bootstrap configuration.
	// See https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/metrics/v3/stats.proto#config-metrics-v3-statsconfig.
	fqn := fmt.Sprintf("waf_filter.action_count.phase_%s.action_%s", phase, actions[a])
	for i := 0; i < len(tagsKV)/2; i++ {
		fqn = fqn + "." + tagsKV[2*i] + "." + tagsKV[2*i+1]
	}
	// TODO(jcchavezs): figure out if we are OK with dynamic creation of metrics
	// or we generate the metrics on before hand.
	counter, ok := m.counters[fqn]
	if !ok {
		counter = proxywasm.DefineCounterMetric(fqn)
		m.counters[fqn] = counter
	}
	counter.Increment(1)
}

func (m *wafMetrics) Duration(phase string, d time.Duration) {
	fqn := fmt.Sprintf("waf_filter.phase_duration.phase_%s", phase)
	histo, ok := m.histograms[fqn]
	if !ok {
		histo = proxywasm.DefineHistogramMetric(fqn)
		m.histograms[fqn] = histo
	}
	histo.Record(uint64(d))
}
