# Coraza Proxy WASM

Web Application Firewall WASM filter built on top of [Coraza](https://github.com/corazawaf/coraza) and implementing on proxy-wasm ABI. It can be loaded directly from Envoy or also used as an Istio plugin.

## Getting started
`go run mage.go -l` lists all the available commands:
```
▶ go run mage.go -l
Targets:
  build*             builds the Coraza Wasm plugin.
  check              runs lint and tests.
  checkBuildTools
  coverage           runs tests with coverage and race detector enabled.
  doc                runs godoc, access at http://localhost:6060
  e2e                runs e2e tests with a built plugin.
  format             formats code in this repository.
  ftw                runs ftw tests with a built plugin and Envoy.
  lint               verifies code quality.
  precommit          installs a git hook to run check when committing
  setup              spins up the test environment.
  teardown           tears down the test environment.
  test               runs all tests.
  updateLibs

* default target
```
### Building the filter
>Note: The build of the Wasm filter currently relies on Go `1.18.*`
```
PATH=/opt/homebrew/Cellar/go@1.18/1.18.6/bin:$PATH  GOROOT=/opt/homebrew/Cellar/go@1.18/1.18.6/libexec go run mage.go build
```
You will find the WASM plugin under `./build/main.wasm`.

For performance purposes, some libs are built from they C++ implementation. The compiled polyglot wasm libs are already checked in under [./lib/](./lib/). It is possible to rely on the Dockerfiles under [./buildtools/](./buildtools/) if you wish to rebuild them from scratch.

### Running the filter in an Envoy process

In order to run the coraza-proxy-wasm we need to spin up an envoy configuration including this as the filter config:

```yaml
    ...

    filter_chains:
    - filters:
        - name: envoy.filters.network.http_connection_manager
            typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
            stat_prefix: ingress_http
            codec_type: auto
            route_config:
                ...
            http_filters:
                - name: envoy.filters.http.wasm
                typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
                    config:
                    name: "coraza-filter"
                    root_id: ""
                    configuration:
                        "@type": "type.googleapis.com/google.protobuf.StringValue"
                        value: |
                        {
                            "rules": "SecDebugLogLevel 5 \nSecRuleEngine On \nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""
                        }
                    vm_config:
                        runtime: "envoy.wasm.runtime.v8"
                        vm_id: "coraza-filter_vm_id"
                        code:
                        local:
                            filename: "build/main.wasm"
```

### Using CRS

Coreruleset comes embeded in the extension, in order to use it in the config, you just need to include it directly in the rules:

Loading entire coreruleset:

```yaml
configuration:
    "@type": "type.googleapis.com/google.protobuf.StringValue"
    value: |
    {
        "rules": "SecDebugLogLevel 5 \nSecRuleEngine On \n Include crs/*.conf"
    }
```

Loading some pieces:

```yaml
configuration:
    "@type": "type.googleapis.com/google.protobuf.StringValue"
    value: |
    {
        "rules": "SecDebugLogLevel 5 \nSecRuleEngine On \n Include crs/REQUEST-901-INITIALIZATION.conf"
    }
```

### Running go-ftw (CRS Regression tests)

The following command runs the [go-ftw](https://github.com/fzipi/go-ftw) test suite against the filter with the CRS fully loaded.
```
go run mage.go build
```
Take a look at its config file [ftw.yml](./ftw/ftw.yml) for details about tests currently excluded.

### Spinning up the coraza-proxy-wasm for manual tests
Via the commands `setup` and `teardown` you can spin up and tear down the test environment. Envoy with the coraza-wasm filter will be reachable at `localhost:8080`.
In order to monitor envoy logs while performing requests run:
```
docker-compose -f ./ftw/docker-compose.yml logs -f envoy-logs
```
