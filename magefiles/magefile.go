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

var minGoVersion = "1.19"
var tinygoMinorVersion = "0.28"
var addLicenseVersion = "04bfe4ee9ca5764577b029acc6a1957fd1997153" // https://github.com/google/addlicense
var golangCILintVer = "v1.48.0"                                    // https://github.com/golangci/golangci-lint/releases
var gosImportsVer = "v0.3.1"                                       // https://github.com/rinchsan/gosimports/releases/tag/v0.3.1

var errCommitFormatting = errors.New("files not formatted, please commit formatting changes")
var errNoGitDir = errors.New("no .git directory found")

func init() {
	for _, check := range []func() error{
		checkTinygoVersion,
		checkGoVersion,
	} {
		if err := check(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}
}

// checkGoVersion checks the minimum version of Go is supported.
func checkGoVersion() error {
	v, err := sh.Output("go", "version")
	if err != nil {
		return fmt.Errorf("unexpected go error: %v", err)
	}

	// Version can/cannot include patch version e.g.
	// - go version go1.19 darwin/arm64
	// - go version go1.19.2 darwin/amd64
	versionRegex := regexp.MustCompile("go([0-9]+).([0-9]+).?([0-9]+)?")
	compare := versionRegex.FindStringSubmatch(v)
	if len(compare) != 4 {
		return fmt.Errorf("unexpected go semver: %q", v)
	}
	compare = compare[1:]
	if compare[2] == "" {
		compare[2] = "0"
	}

	base := strings.SplitN(minGoVersion, ".", 3)
	if len(base) == 2 {
		base = append(base, "0")
	}
	for i := 0; i < 3; i++ {
		baseN, _ := strconv.Atoi(base[i])
		compareN, _ := strconv.Atoi(compare[i])
		if baseN > compareN {
			return fmt.Errorf("unexpected go version, minimum want %q, have %q", minGoVersion, strings.Join(compare, "."))
		}
	}
	return nil
}

// checkTinygoVersion checks that exactly the right tinygo version is supported because
// tinygo isn't stable yet.
func checkTinygoVersion() error {
	v, err := sh.Output("tinygo", "version")
	if err != nil {
		return fmt.Errorf("unexpected tinygo error: %v", err)
	}

	// Assume a dev build is valid.
	if strings.Contains(v, "-dev") {
		return nil
	}

	if !strings.HasPrefix(v, fmt.Sprintf("tinygo version %s", tinygoMinorVersion)) {
		return fmt.Errorf("unexpected tinygo version, wanted %s", tinygoMinorVersion)
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

	buildTags := []string{"custommalloc", "no_fs_access"}
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
	if err := sh.RunV("docker-compose", "--file", "e2e/docker-compose.yml", "build", "--pull"); err != nil {
		return err
	}
	return sh.RunV("docker-compose", "-f", "e2e/docker-compose.yml", "up", "--abort-on-container-exit", "tests")
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

// RunExample spins up the test environment, access at http://localhost:8080. Requires docker-compose.
func RunExample() error {
	return sh.RunWithV(map[string]string{"ENVOY_IMAGE": os.Getenv("ENVOY_IMAGE")}, "docker-compose", "--file", "example/docker-compose.yml", "up", "-d", "envoy-logs")
}

// TeardownExample tears down the test environment. Requires docker-compose.
func TeardownExample() error {
	return sh.RunV("docker-compose", "--file", "example/docker-compose.yml", "down")
}

// ReloadExample reload the test environment (container) in case of envoy or wasm update. Requires docker-compose
func ReloadExample() error {
	return sh.RunV("docker-compose", "--file", "example/docker-compose.yml", "restart")
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
