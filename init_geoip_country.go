// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build geoip-country && !geoip-city

package main

import (
	_ "embed"

	geo "github.com/woehrl01/coraza-geoip"
)

//go:embed geoip.mmdb
var geoDatabase []byte

func init() {
	geo.RegisterGeoDatabase(geoDatabase, "country")
}
