// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Copied from https://github.com/corazawaf/coraza/blob/v3/dev/bodyprocessors/xml.go
// This currently does not work with released TinyGo versions so Coraza cannot enable XML
// on TinyGo by default, but we build this repo with a fork including the fix for XML and
// enable it here by reimplementing.

package bodyprocessors

import (
	"encoding/xml"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3/bodyprocessors"
	"github.com/corazawaf/coraza/v3/rules"
)

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, vars rules.TransactionVariables, _ bodyprocessors.Options) error {
	values, contents, err := readXML(reader)
	if err != nil {
		return err
	}
	col := vars.RequestXML()
	col.Set("//@*", values)
	col.Set("/*", contents)
	return nil
}

func (*xmlBodyProcessor) ProcessResponse(io.Reader, rules.TransactionVariables, bodyprocessors.Options) error {
	return nil
}

func readXML(reader io.Reader) ([]string, []string, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
	for {
		token, err := dec.Token()
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		if token == nil {
			break
		}
		switch tok := token.(type) {
		case xml.StartElement:
			for _, attr := range tok.Attr {
				attrs = append(attrs, attr.Value)
			}
		case xml.CharData:
			if c := strings.TrimSpace(string(tok)); c != "" {
				content = append(content, c)
			}
		}
	}
	return attrs, content, nil
}

var (
	_ bodyprocessors.BodyProcessor = &xmlBodyProcessor{}
)

func Register() {
	bodyprocessors.Register("xml", func() bodyprocessors.BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
