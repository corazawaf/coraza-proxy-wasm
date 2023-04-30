// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build disable_metrics

package wasmplugin

type wafMetrics struct{}

func NewWAFMetrics() *wafMetrics {
	return &wafMetrics{}
}

func (*wafMetrics) CountTX() {}

func (*wafMetrics) CountTXInterruption(_ string, _ int) {}
