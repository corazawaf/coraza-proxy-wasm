// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build geoip_city && !geoip_country

package main

import (
	_ "embed"

	geo "github.com/corazawaf/coraza-geoip"
)

//go:embed geoip.mmdb
var geoDatabase []byte

func init() {
	_ = geo.RegisterGeoDatabase(geoDatabase, "country")
}
