// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"

	"fortio.org/fortio/fhttp"
	"fortio.org/fortio/periodic"
	"github.com/magefile/mage/sh"
)

// LoadTest runs load tests against the ftw deployment.
func LoadTest() error {
	if err := sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "build", "--pull"); err != nil {
		return err
	}
	defer func() {
		_ = sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "kill")
		_ = sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "down", "-v")
	}()
	if err := sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "run", "--service-ports", "--rm", "-d", "envoy"); err != nil {
		return err
	}

	opts := &fhttp.HTTPRunnerOptions{
		RunnerOptions: periodic.RunnerOptions{
			QPS:        100,
			NumThreads: 1,
			Duration:   10 * time.Second,
		},
		AllowInitialErrors: true,
		HTTPOptions: fhttp.HTTPOptions{
			URL: "http://localhost:8080/",
		},
	}

	res, err := fhttp.RunHTTPTest(opts)
	if err != nil {
		return err
	}
	rr := res.Result()
	fmt.Printf("All done %d calls (plus %d warmup) %.3f ms avg, %.1f qps\n",
		rr.DurationHistogram.Count,
		0,
		1000.*rr.DurationHistogram.Avg,
		rr.ActualQPS)

	return nil
}
