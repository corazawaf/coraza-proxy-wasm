// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/magefile/mage/sh"
	"golang.org/x/net/http2"
)

// E2e runs e2e tests. Requires docker.
func E2e() error {
	envoyHost := cmp.Or(os.Getenv("ENVOY_HOST"), "localhost:8080")
	httpbinHost := cmp.Or(os.Getenv("HTTPBIN_HOST"), "localhost:8081")

	if err := runCorazaE2e(envoyHost, httpbinHost); err != nil {
		return err
	}

	if err := runHttpTrailerE2e(envoyHost); err != nil {
		return err
	}
	return nil
}

// runCorazaE2e runs Coraza e2e tests with a built plugin against the example deployment
func runCorazaE2e(envoyHost, httpbinHost string) error {
	dockerComposeFilePath := "e2e/coraza/docker-compose.yml"
	var err error
	if err = sh.RunV("docker", "compose", "--file", dockerComposeFilePath, "up", "-d", "envoy"); err != nil {
		sh.RunV("docker", "compose", "-f", dockerComposeFilePath, "logs", "envoy")
		return err
	}
	defer func() {
		_ = sh.RunV("docker", "compose", "--file", dockerComposeFilePath, "down", "-v")
	}()

	// --nulled-body is needed because coraza-proxy-wasm returns a 200 OK with a nulled body when if the interruption happens after phase 3
	if err = sh.RunV("go", "run", "github.com/corazawaf/coraza/v3/http/e2e/cmd/httpe2e@main", "--proxy-hostport",
		"http://"+envoyHost, "--httpbin-hostport", "http://"+httpbinHost, "--nulled-body"); err != nil {
		sh.RunV("docker", "compose", "-f", dockerComposeFilePath, "logs", "envoy")
	}
	return err
}

// runHttpTrailerE2e runs HTTP trailer E2E tests
// It is meant to check that HTTP2 request payloads with trailers are scanned at phase 2 before being sent to upstream.
// This might happen because the end_of_stream parameter from OnHttpRequestBody is never set to true in HTTP2 if trailers
// are available. In order to mitigate this, OnHttp[Request|Response]Trailers callbacks have been implemented as an enforcement
// point of the body phase rules.
// The test expects Coraza to enforce the interruption (403) during phase="http_request_body" and not phase="http_response_headers",
// which would mean that the payload was sent to upstream before being scanned and was blocked on the way back.
func runHttpTrailerE2e(envoyHost string) error {
	fmt.Printf("Running HTTP trailer test\n")
	dockerComposeFilePath := "e2e/http_trailer/docker-compose.yml"
	if err := sh.RunV("go", "run", "filippo.io/mkcert@v1.4.4", "-key-file", "e2e/http_trailer/server.key",
		"-cert-file", "e2e/http_trailer/server.crt", "example.com"); err != nil {
		return err
	}
	defer func() {
		_ = os.Remove("e2e/http_trailer/server.key")
		_ = os.Remove("e2e/http_trailer/server.crt")
	}()
	if err := sh.RunV("docker", "compose", "--file", dockerComposeFilePath, "up", "-d", "envoy"); err != nil {
		sh.RunV("docker", "compose", "-f", dockerComposeFilePath, "logs", "envoy")
		return err
	}
	defer func() {
		_ = sh.RunV("docker", "compose", "--file", dockerComposeFilePath, "down", "-v")
	}()

	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Wait for envoy to be ready
	ready := false
	for range 20 {
		resp, err := client.Get("https://" + envoyHost)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(500 * time.Millisecond)
		fmt.Println("Waiting for Envoy to be ready...")
	}
	if !ready {
		sh.RunV("docker", "compose", "-f", dockerComposeFilePath, "logs", "envoy")
		return fmt.Errorf("timeout waiting for Envoy")
	}

	// Run the actual test.
	req, err := http.NewRequest("POST", "https://"+envoyHost, strings.NewReader("{\"foo\": \"<script foo>\"}"))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Trailer = http.Header{"Custom-Trailer": {"This is a custom trailer"}}

	resp, err := client.Do(req)
	if err != nil {
		sh.RunV("docker", "compose", "-f", dockerComposeFilePath, "logs", "envoy")
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	output, err := sh.Output("docker", "compose", "-f", dockerComposeFilePath, "logs", "envoy")
	if err != nil {
		return fmt.Errorf("getting envoy logs: %w", err)
	}

	// The request is expected to be blocked at phase 2, before reaching the backend.
	if resp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if !strings.Contains(output, "phase=\"http_request_body\"") {
		return fmt.Errorf("expected phase=\"http_request_body\" in envoy logs transaction interrupted line, got:\n%s", output)
	}
	fmt.Printf("✅ HTTP trailer test passed\n")

	return nil
}
