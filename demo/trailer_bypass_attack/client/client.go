// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/http2"
)

func main() {
	url := "https://localhost:8080"

	req, err := http.NewRequest(
		"POST",
		url,
		strings.NewReader(
			"{\"foo\": \"<script foo>\"}",
		),
	)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	if len(os.Args) > 1 && os.Args[1] == "-a" {
		req.Trailer = http.Header{
			"Custom-Trailer": {"This is a custom trailer"},
		}
	}

	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}
	fmt.Println("Response body:", string(body))
}
