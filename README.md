# Coraza WASM filter

Web Application Firewall WASM filter built on top of Coraza and implementing on proxy-wasm ABI. It can be loaded directlu from Envoy or also used as an istio plugin.

## Getting started

In order to run the coraza-wasm-filter we need to spin up an envoy configuration including this the filter config:

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
