# Coraza Proxy WASM as WasmPlugin for Istio

WasmPlugins allow the Istio proxy to be enhanced with WebAssembly filters. 
The coraza proxy wasm acts as one of these filters, adding WAF features to Istio. 
The execution order within Envoy's filter chain is set by phase and priority, facilitating 
intricate interactions between user-provided WasmPlugins and Istio's built-in filters.

## Istio Setup

Given a multitude of possible Istio setups, we will only cover the most common one with the following assumptions:

- Istio is installed in the `istio-system` namespace
- The mesh has an entrypoint served by a `istio-ingressgateway` service
- Services served by Istio have an `istio-proxy` sidecar

## Getting started

The coraza proxy wasm can filter traffic inside the mesh at multiple locations.

### At Ingress gateway for all incoming traffic

The envoy pod of the ingress-gateway can be configured to use the coraza proxy wasm as a filter, thus 
filtering all incoming traffic.

The following example shows how to configure embedded [Core Rule Set](https://github.com/coreruleset/coreruleset)
at the ingress gateway and use the coraza proxy wasm as a filter.

It utilizes the 
[WasmPlugin](https://istio.io/latest/docs/reference/config/proxy_extensions/wasm-plugin/) resource of Istio.
This way the filter can be configured via the `pluginConfig` field and envoy configuration is abstracted away.

```yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: coraza-ingressgateway
  namespace: istio-ingress
spec:
  imagePullPolicy: IfNotPresent
  phase: AUTHN
  pluginConfig:
    default_directives: default
    directives_map:
      default:
      - Include @demo-conf
      - SecDebugLogLevel 9
      - SecRuleEngine On
      - Include @crs-setup-demo-conf
      - Include @owasp_crs/*.conf
  selector:
    matchLabels:
      app: istio-ingressgateway
      istio: ingressgateway
  url: oci://ghcr.io/corazawaf/coraza-proxy-wasm
```

The `selector` needs to match labels attached to the pods of the ingress gateway.
The `url` points to the OCI image of the coraza proxy wasm, which is provided by the project.

All traffic entering the mesh via the ingress gateway will now be filtered by the coraza proxy wasm 
and violations will be logged to the istio-proxy's log and a `403 Forbidden` response will be returned to the client.

### At each namespace individually

Traffic which has successfully passed the ingress gateway can be filtered at each namespace individually using
a similar approach as above. 
The following example will show how to load the entire [Core Rule Set](https://github.com/coreruleset/coreruleset).

```yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: coraza-core-rule-set
  namespace: my-app
spec:
  imagePullPolicy: IfNotPresent
  phase: AUTHN
  pluginConfig:
    default_directives: default
    directives_map:
      default:
      - Include @demo-conf
      - SecDebugLogLevel 9
      - SecRuleEngine On
      - Include @crs-setup-demo-conf
      - Include @owasp_crs/*.conf
  selector:
    matchLabels:
      app: my-app
  url: oci://ghcr.io/corazawaf/coraza-proxy-wasm
```

The `selector` needs to match labels attached to the pods of the namespace where filtering is desired.
The `namespace` field needs to match the namespace of the pods.

All traffic entering the namespace  will now be filtered by the coraza proxy wasm using the
entire [Core Rule Set](https://github.com/coreruleset/coreruleset) and 
violations will be logged to the istio-proxy's log and a `403 Forbidden` response will be returned to the client.

Traffic which has already been filtered by the ingress gateway will not reach the namespace and will only be 
logged to the istio-proxy's log in the namespace of the ingress-gateway.

## Testing and Logs

The coraza proxy wasm logs violations to the istio-proxy's log.

The following example shows a violation to the rule `REQUEST-941-APPLICATION-ATTACK-XSS` which is included in the
istio-ingressgateways filter configuration.

```bash
curl 'https://my-app.my-domain.com/anything?arg=<script>alert(0)</script>' -IL
HTTP/2 403
vary: Accept-Encoding
date: Tue, 10 Oct 2023 13:45:47 GMT
server: istio-envoy
```

Depending on your configuration a log in the istio-proxy's log will look like this:

```text
envoy wasm external/envoy/source/extensions/common/wasm/context.cc:1157	
wasm log istio-ingress.coraza-ingressgateway: [client "my-client"] 
Coraza: Warning. Javascript method detected [file "@owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] 
[line "7982"] [id "941390"] [rev ""] [msg "Javascript method detected"] 
[data "Matched Data: alert( found within ARGS_GET:arg: <script>alert(0)</script>"] 
[severity "critical"] [ver "OWASP_CRS/4.0.0-rc1"] [maturity "0"] [accuracy "0"] 
[tag "application-multi"] [tag "language-multi"] [tag "attack-xss"] [tag "paranoia-level/1"] 
[tag "OWASP_CRS"] [tag "capec/1000/152/242"] [hostname "my-hostname"] [uri "/anything/?arg=<script>alert(0)</script>"] 
[unique_id "wTueIQloYpvpWNLzVfy"]	thread=27
```