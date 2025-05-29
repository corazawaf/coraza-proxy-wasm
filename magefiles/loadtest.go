// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"fortio.org/fortio/fhttp"
	"fortio.org/fortio/fnet"
	"fortio.org/fortio/periodic"
	"github.com/magefile/mage/sh"
)

const (
	durationPerTest = 10 * time.Second
	qpsPerTest      = 100
)

// LoadTest runs load tests against the ftw deployment. Requires docker
func LoadTest() error {
	var results []LoadTestResult
	for _, threads := range []int{1, 2, 4} {
		for _, payloadSize := range []int{0, 100, 1000, 10000} {
			for _, conf := range []string{"envoy-config.yaml", "envoy-config-nowasm.yaml"} {
				result, err := doLoadTest(conf, payloadSize, threads)
				if err != nil {
					return err
				}
				results = append(results, result)
			}
		}
	}
	fmt.Printf("Load Test Results:\nDuration per test: %s\nAttempted QPS per test: %d\n", durationPerTest, qpsPerTest)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "Config\tPayloadSize\tThreads\tCount\tAvgLatency(ms)\t\tQPS")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%.3f\t\t%.1f\n",
			r.config, r.payloadSize, r.threads, r.count, r.avgLatency, r.qps)
	}
	w.Flush()
	return nil
}

func doLoadTest(conf string, payloadSize int, threads int) (LoadTestResult, error) {
	if err := sh.RunV("docker", "compose", "--file", "ftw/docker-compose.yml", "build", "--pull"); err != nil {
		return LoadTestResult{}, err
	}
	defer func() {
		_ = sh.RunV("docker", "compose", "--file", "ftw/docker-compose.yml", "kill")
		_ = sh.RunV("docker", "compose", "--file", "ftw/docker-compose.yml", "down", "-v")
	}()
	if err := sh.RunWithV(map[string]string{"ENVOY_CONFIG": fmt.Sprintf("/conf/%s", conf)}, "docker", "compose",
		"--file", "ftw/docker-compose.yml", "run", "--service-ports", "--rm", "-d", "envoy"); err != nil {
		return LoadTestResult{}, err
	}

	// Wait for Envoy to start.
	for range 1000 {
		if resp, err := http.Get("http://localhost:8080/anything"); err != nil {
		} else {
			if resp.Body != nil {
				resp.Body.Close()
			}
			if resp.StatusCode == http.StatusOK {
				fmt.Println("Envoy ready")
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	opts := &fhttp.HTTPRunnerOptions{
		RunnerOptions: periodic.RunnerOptions{
			QPS:        qpsPerTest,
			NumThreads: threads,
			Duration:   durationPerTest,
		},
		HTTPOptions: fhttp.HTTPOptions{
			URL:     "http://localhost:8080/anything",
			Payload: fnet.GenerateRandomPayload(payloadSize),
		},
	}

	fmt.Printf("Running load test with config=%s, payloadSize=%d, threads=%d\n", conf, payloadSize, threads)
	res, err := fhttp.RunHTTPTest(opts)
	if err != nil {
		return LoadTestResult{}, err
	}
	rr := res.Result()
	fmt.Printf("All done %d calls (plus %d warmup) %.3f ms avg, %.1f qps\n",
		rr.DurationHistogram.Count,
		0,
		1000.*rr.DurationHistogram.Avg,
		rr.ActualQPS)

	return LoadTestResult{
		config:      conf,
		payloadSize: payloadSize,
		threads:     threads,
		count:       rr.DurationHistogram.Count,
		avgLatency:  1000. * rr.DurationHistogram.Avg,
		qps:         rr.ActualQPS,
	}, nil
}

type LoadTestResult struct {
	config      string
	payloadSize int
	threads     int
	count       int64
	avgLatency  float64
	qps         float64
}
