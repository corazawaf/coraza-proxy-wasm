// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !memstats

package wasmplugin

func logMemStats() {
	// no-op without build tag
}
