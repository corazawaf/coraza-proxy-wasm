// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/tetratelabs/wabin/binary"
	"github.com/tetratelabs/wabin/wasm"
)

var minGoVersion = "1.20"
var minTinygoVersion = "0.30"
var addLicenseVersion = "04bfe4ee9ca5764577b029acc6a1957fd1997153" // https://github.com/google/addlicense
var golangCILintVer = "v1.54.2"                                    // https://github.com/golangci/golangci-lint/releases
var gosImportsVer = "v0.3.1"                                       // https://github.com/rinchsan/gosimports/releases/tag/v0.3.1

var errCommitFormatting = errors.New("files not formatted, please commit formatting changes")

func init() {
	for _, check := range []struct {
		lang       string
		minVersion string
	}{
		{"tinygo", minTinygoVersion},
		{"go", minGoVersion},
	} {
		if err := checkVersion(check.lang, check.minVersion); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}
}

// checkVersion checks the minimum version of the specified language is supported.
// Note: While it is likely, there are no guarantees that a newer version of the language will work
func checkVersion(lang string, minVersion string) error {
	var compare []string

	switch lang {
	case "go":
		// Version can/cannot include patch version e.g.
		// - go version go1.19 darwin/arm64
		// - go version go1.19.2 darwin/amd64
		goVersionRegex := regexp.MustCompile("go([0-9]+).([0-9]+).?([0-9]+)?")
		v, err := sh.Output("go", "version")
		if err != nil {
			return fmt.Errorf("unexpected go error: %v", err)
		}
		compare = goVersionRegex.FindStringSubmatch(v)
		if len(compare) != 4 {
			return fmt.Errorf("unexpected go semver: %q", v)
		}
	case "tinygo":
		tinygoVersionRegex := regexp.MustCompile("tinygo version ([0-9]+).([0-9]+).?([0-9]+)?")
		v, err := sh.Output("tinygo", "version")
		if err != nil {
			return fmt.Errorf("unexpected tinygo error: %v", err)
		}
		// Assume a dev build is valid.
		if strings.Contains(v, "-dev") {
			return nil
		}
		compare = tinygoVersionRegex.FindStringSubmatch(v)
		if len(compare) != 4 {
			return fmt.Errorf("unexpected tinygo semver: %q", v)
		}
	default:
		return fmt.Errorf("unexpected language: %s", lang)
	}

	compare = compare[1:]
	if compare[2] == "" {
		compare[2] = "0"
	}

	base := strings.SplitN(minVersion, ".", 3)
	if len(base) == 2 {
		base = append(base, "0")
	}
	for i := 0; i < 3; i++ {
		baseN, _ := strconv.Atoi(base[i])
		compareN, _ := strconv.Atoi(compare[i])
		if baseN > compareN {
			return fmt.Errorf("unexpected %s version, minimum want %q, have %q", lang, minVersion, strings.Join(compare, "."))
		}
	}
	return nil
}

// Format formats code in this repository.
func Format() error {
	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}
	// addlicense strangely logs skipped files to stderr despite not being erroneous, so use the long sh.Exec form to
	// discard stderr too.
	if _, err := sh.Exec(map[string]string{}, io.Discard, io.Discard, "go", "run", fmt.Sprintf("github.com/google/addlicense@%s", addLicenseVersion),
		"-c", "The OWASP Coraza contributors",
		"-s=only",
		"-y=",
		"-ignore", "**/*.yml",
		"-ignore", "**/*.yaml",
		"-ignore", "examples/**", "."); err != nil {
		return err
	}
	return sh.RunV("go", "run", fmt.Sprintf("github.com/rinchsan/gosimports/cmd/gosimports@%s", gosImportsVer),
		"-w",
		"-local",
		"github.com/corazawaf/coraza-proxy-wasm",
		".")
}

// Lint verifies code quality.
func Lint() error {
	if err := sh.RunV("go", "run", fmt.Sprintf("github.com/golangci/golangci-lint/cmd/golangci-lint@%s", golangCILintVer), "run"); err != nil {
		return err
	}

	mg.SerialDeps(Format)

	if sh.Run("git", "diff", "--exit-code") != nil {
		return errCommitFormatting
	}

	return nil
}

// Test runs all unit tests.
func Test() error {
	// by default multiphase is enabled
	if os.Getenv("MULTIPHASE_EVAL") == "false" {
		return sh.RunV("go", "test", "./...")
	}
	return sh.RunV("go", "test", "-tags=coraza.rule.multiphase_evaluation", "./...")
}

// Coverage runs tests with coverage and race detector enabled.
func Coverage() error {
	if err := os.MkdirAll("build", 0755); err != nil {
		return err
	}

	if _, err := os.Stat("build/mainraw.wasm"); err != nil {
		return errors.New("build/mainraw.wasm not found, please run `go run mage.go build`")
	}

	if os.Getenv("MULTIPHASE_EVAL") == "false" {
		// Test coraza-wasm filter without multiphase evaluation
		if err := sh.RunV("go", "test", "-race", "-coverprofile=build/coverage.txt", "-covermode=atomic", "-coverpkg=./...", "./..."); err != nil {
			return err
		}
		return sh.RunV("go", "tool", "cover", "-html=build/coverage.txt", "-o", "build/coverage.html")

	} else {
		// Test coraza-wasm filter with multiphase evaluation
		if err := sh.RunV("go", "test", "-race", "-coverprofile=build/coverage_multi.txt", "-covermode=atomic", "-coverpkg=./...", "-tags=coraza.rule.multiphase_evaluation", "./..."); err != nil {
			return err
		}
		return sh.RunV("go", "tool", "cover", "-html=build/coverage_multi.txt", "-o", "build/coverage.html")
	}
}

// Doc runs godoc, access at http://localhost:6060
func Doc() error {
	return sh.RunV("go", "run", "golang.org/x/tools/cmd/godoc@latest", "-http=:6060")
}

// Check runs lint and tests.
func Check() {
	mg.SerialDeps(Lint, Test)
}

// Build builds the Coraza wasm plugin.
func Build() error {
	if err := os.MkdirAll("build", 0755); err != nil {
		return err
	}

	buildTags := []string{
		"custommalloc",     // https://github.com/wasilibs/nottinygc#usage
		"no_fs_access",     // https://github.com/corazawaf/coraza#build-tags
		"memoize_builders", // https://github.com/corazawaf/coraza#build-tags
	}
	// By default multiphase evaluation is enabled
	if os.Getenv("MULTIPHASE_EVAL") != "false" {
		buildTags = append(buildTags, "coraza.rule.multiphase_evaluation")
	}
	if os.Getenv("TIMING") == "true" {
		buildTags = append(buildTags, "timing", "proxywasm_timing")
	}
	if os.Getenv("MEMSTATS") == "true" {
		buildTags = append(buildTags, "memstats")
	}

	buildTagArg := fmt.Sprintf("-tags='%s'", strings.Join(buildTags, " "))

	// ~100MB initial heap
	initialPages := 2100
	if ipEnv := os.Getenv("INITIAL_PAGES"); ipEnv != "" {
		if ip, err := strconv.Atoi(ipEnv); err != nil {
			return err
		} else {
			initialPages = ip
		}
	}

	if err := sh.RunV("tinygo", "build", "-gc=custom", "-opt=2", "-o", filepath.Join("build", "mainraw.wasm"), "-scheduler=none", "-target=wasi", buildTagArg); err != nil {
		return err
	}

	return patchWasm(filepath.Join("build", "mainraw.wasm"), filepath.Join("build", "main.wasm"), initialPages)
}

// E2e runs e2e tests with a built plugin against the example deployment. Requires docker-compose.
func E2e() error {
	var err error
	if err = sh.RunV("docker-compose", "--file", "e2e/docker-compose.yml", "up", "-d", "envoy"); err != nil {
		return err
	}
	defer func() {
		_ = sh.RunV("docker-compose", "--file", "e2e/docker-compose.yml", "down", "-v")
	}()

	envoyHost := os.Getenv("ENVOY_HOST")
	if envoyHost == "" {
		envoyHost = "localhost:8080"
	}
	httpbinHost := os.Getenv("HTTPBIN_HOST")
	if httpbinHost == "" {
		httpbinHost = "localhost:8081"
	}

	// --nulled-body is needed because coraza-proxy-wasm returns a 200 OK with a nulled body when if the interruption happens after phase 3
	if err = sh.RunV("go", "run", "github.com/corazawaf/coraza/v3/http/e2e/cmd/httpe2e@main", "--proxy-hostport",
		"http://"+envoyHost, "--httpbin-hostport", "http://"+httpbinHost, "--nulled-body"); err != nil {
		sh.RunV("docker-compose", "-f", "e2e/docker-compose.yml", "logs", "envoy")
	}
	return err
}

// Ftw runs ftw tests with a built plugin and Envoy. Requires docker-compose.
func Ftw() error {
	if err := sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "build", "--pull"); err != nil {
		return err
	}
	defer func() {
		_ = sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "down", "-v")
	}()
	env := map[string]string{
		"FTW_CLOUDMODE": os.Getenv("FTW_CLOUDMODE"),
		"FTW_INCLUDE":   os.Getenv("FTW_INCLUDE"),
		"ENVOY_IMAGE":   os.Getenv("ENVOY_IMAGE"),
	}
	if os.Getenv("ENVOY_NOWASM") == "true" {
		env["ENVOY_CONFIG"] = "/conf/envoy-config-nowasm.yaml"
	}
	task := "ftw"
	if os.Getenv("MEMSTATS") == "true" {
		task = "ftw-memstats"
	}
	return sh.RunWithV(env, "docker-compose", "--file", "ftw/docker-compose.yml", "run", "--rm", task)
}

// RunEnvoyExample spins up the test environment of envoy, access at http://localhost:8080. Requires docker-compose.
func RunEnvoyExample() error {
	return sh.RunWithV(map[string]string{"ENVOY_IMAGE": os.Getenv("ENVOY_IMAGE")}, "docker-compose", "--file", "example/envoy/docker-compose.yml", "up")
}

// TeardownEnvoyExample tears down the test environment of envoy. Requires docker-compose.
func TeardownEnvoyExample() error {
	return sh.RunV("docker-compose", "--file", "example/envoy/docker-compose.yml", "down")
}

// ReloadEnvoyExample reload the test environment (container) of envoy in case of envoy or wasm update. Requires docker-compose
func ReloadEnvoyExample() error {
	return sh.RunV("docker-compose", "--file", "example/envoy/docker-compose.yml", "restart")
}

var Default = Build

func patchWasm(inPath, outPath string, initialPages int) error {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	mod, err := binary.DecodeModule(raw, wasm.CoreFeaturesV2)
	if err != nil {
		return err
	}

	mod.MemorySection.Min = uint32(initialPages)

	for _, imp := range mod.ImportSection {
		switch {
		case imp.Name == "fd_filestat_get":
			imp.Name = "fd_fdstat_get"
		case imp.Name == "path_filestat_get":
			imp.Module = "env"
			imp.Name = "proxy_get_header_map_value"
		}
	}

	out := binary.EncodeModule(mod)
	if err = os.WriteFile(outPath, out, 0644); err != nil {
		return err
	}

	return nil
}
