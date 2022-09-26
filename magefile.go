// Copyright 2022 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var addLicenseVersion = "v1.0.0" // https://github.com/google/addlicense
var golangCILintVer = "v1.48.0"  // https://github.com/golangci/golangci-lint/releases
var gosImportsVer = "v0.3.1"     // https://github.com/rinchsan/gosimports/releases/tag/v0.3.1

var errCommitFormatting = errors.New("files not formatted, please commit formatting changes")
var errNoGitDir = errors.New("no .git directory found")

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
		"-ignore", "**/*.yml",
		"-ignore", "**/*.yaml",
		"-ignore", "examples/**", "."); err != nil {
		return err
	}
	return sh.RunV("go", "run", fmt.Sprintf("github.com/rinchsan/gosimports/cmd/gosimports@%s", gosImportsVer),
		"-w",
		"-local",
		"github.com/jcchavezs/coraza-wasm-filter",
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

// Test runs all tests.
func Test() error {
	return sh.RunV("go", "test", "./...")
}

// Coverage runs tests with coverage and race detector enabled.
func Coverage() error {
	if err := os.MkdirAll("build", 0755); err != nil {
		return err
	}
	if err := sh.RunV("go", "test", "-race", "-coverprofile=build/coverage.txt", "-covermode=atomic", "-coverpkg=./...", "./..."); err != nil {
		return err
	}

	return sh.RunV("go", "tool", "cover", "-html=build/coverage.txt", "-o", "build/coverage.html")
}

// Doc runs godoc, access at http://localhost:6060
func Doc() error {
	return sh.RunV("go", "run", "golang.org/x/tools/cmd/godoc@latest", "-http=:6060")
}

// Precommit installs a git hook to run check when committing
func Precommit() error {
	if _, err := os.Stat(filepath.Join(".git", "hooks")); os.IsNotExist(err) {
		return errNoGitDir
	}

	f, err := os.ReadFile(".pre-commit.hook")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(".git", "hooks", "pre-commit"), f, 0755)
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
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	timingBuildTag := ""
	if os.Getenv("TIMING") == "true" {
		timingBuildTag = "-tags 'timing proxywasm_timing'"
	}

	script := fmt.Sprintf(`
cd /src && \
tinygo build -opt 2 -o build/mainraw.wasm -scheduler=none -target=wasi %s . && \
wasm-opt -Os -c build/mainraw.wasm -o build/mainopt.wasm && \
wasm2wat --enable-all build/mainopt.wasm -o build/mainopt.wat
`, timingBuildTag)

	if err := sh.RunV("docker", "run", "--pull", "always", "--rm", "-v", fmt.Sprintf("%s:/src", wd), "ghcr.io/anuraaga/coraza-wasm-filter/buildtools-tinygo:main", "bash", "-c",
		strings.TrimSpace(script)); err != nil {
		return err
	}

	watBytes, err := os.ReadFile(filepath.Join("build", "mainopt.wat"))
	if err != nil {
		return err
	}
	wat := string(watBytes)
	wat = strings.ReplaceAll(wat, "fd_filestat_get", "fd_fdstat_get")
	wat = strings.ReplaceAll(wat, `"wasi_snapshot_preview1" "path_filestat_get"`, `"env" "proxy_get_header_map_value"`)
	err = os.WriteFile(filepath.Join("build", "main.wat"), []byte(wat), 0644)
	if err != nil {
		return err
	}
	return sh.RunV("docker", "run", "--rm", "-v", fmt.Sprintf("%s:/build", filepath.Join(wd, "build")), "ghcr.io/anuraaga/coraza-wasm-filter/buildtools-tinygo:main", "bash", "-c",
		"wat2wasm --enable-all /build/main.wat -o /build/main.wasm")
}

func UpdateLibs() error {
	libs := []string{"aho-corasick", "libinjection", "re2"}
	for _, lib := range libs {
		if err := sh.RunV("docker", "build", "-t", "ghcr.io/anuraaga/coraza-wasm-filter/buildtools-"+lib, filepath.Join("buildtools", lib)); err != nil {
			return err
		}
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		if err := sh.RunV("docker", "run", "-it", "--rm", "-v", fmt.Sprintf("%s:/out", filepath.Join(wd, "lib")), "ghcr.io/anuraaga/coraza-wasm-filter/buildtools-"+lib); err != nil {
			return err
		}
	}
	return nil
}

// E2e runs e2e tests with a built plugin. Requires docker-compose.
func E2e() error {
	return sh.RunV("docker-compose", "--file", "e2e/docker-compose.yml", "up", "--abort-on-container-exit")
}

// Ftw runs ftw tests with a built plugin and Envoy. Requires docker-compose.
func Ftw() error {
	if err := sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "build"); err != nil {
		return err
	}
	defer func() {
		_ = sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "down", "-v")
	}()
	env := map[string]string{
		"FTW_CLOUDMODE": os.Getenv("FTW_CLOUDMODE"),
	}
	if os.Getenv("ENVOY_NOWASM") == "true" {
		env["ENVOY_CONFIG"] = "/conf/envoy-config-nowasm.yaml"
	}
	return sh.RunWithV(env, "docker-compose", "--file", "ftw/docker-compose.yml", "run", "--rm", "ftw")
}

var Default = Build
