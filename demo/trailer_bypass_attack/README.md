# HTTP Trailers Vulnerability

This folder contains the configuration, certificates and the code necessary
for demonstrating the HTTP Trailers vulnerability in Coraza WASM Project.

# Overview

The Envoy exposes set of functions for HTTP Filters, which include methods such
as:

* onRequestHeaders
* onRequestData
* onRequestTrailers

etc. (depending on the language SDK names of these methods may vary)

The onRequestData call provides two parameters:
* payload chunk
* end_of_stream

The end_of_stream parameter definition may be unclear - it is set to
true if:
* there are no more payload chunks to process
* there are no HTTP trailers

The second point is important as trailers are processed AFTER the payload.
Which means that under the presence of trailers, the onRequestData will
**NOT** be called with `end_of_stream = true`. It may happen with HTTP 2
requests as Envoy Proxy ignores request trailers for HTTP 1 requests.

## Coraza bug

The present implementation triggers Coraza Request Body Threat scanning
after the entire payload is collected. It is verified by checking if
end_of_stream variable is set to true.

However, when HTTP 2 request contains trailers, such scanning will be
bypassed, as Envoy instead of calling `onRequestData(..., eos = true)`
will call `onRequestTrailers(...)`. This method is not overwritten
so the scanning will not be performed at this stage and so the payload
will be sent entirely to the upstream - while holding a potential web
attack.

Since existing implementation performs scanning at the end of the stream
as well, the attack will be detected after processing the response.
The problem is that, malformed payload should not receive the server.
And that's the existing vulnerability:

```
The request payload scanning will occur to late for HTTP 2 requests
with trailers resulting in malicious payloads reaching the upstream
server.
```

# Solution

The fix implements `onRequestTrailers` method which calls `onRequestBody`
method with parameter `end_of_stream` set to true to trigger the
existing scanning implementation.

# Testing

To demonstrate the vulnerability, the testing client and server
were introduced along with example envoy configuration and certificates.

## Code

### Client

The Client is a Go client which sends an HTTP 2 POST Request to
`localhost:8080` with malicious payload containing XSS attempt.
```bash
go run client.go
```

To send a request with HTTP trailer, add `-a` argument
```bash
go run client.go -a
```

### Server

The server is a Python Flask server which starts listening for
HTTP requests on `0.0.0.0:8005`.

The server waits 2 seconds before sending the response so that
the tester can observe logs of the flask server and envoy proxy.

### Envoy Config

Envoy configuration is similar to the configuration from
`example/envoy/envoy-config.yaml` with the difference that it
includes certificates for SSL connection and HTTP2 connections.

### Certs

Sample generated certificates for testing purposes.

## Testing analysis

### Before the fix

To examine the issue, build the WASM filter without the fix
(either omit this commit or comment `OnHttpRequestTrailers`
method from wasmplugin/plugin.go).

Then:

1. Install and start flask server
    ```bash
    pip3 install -r server/requirements.txt
    python3 server/server.py
    ```

1. Run Envoy with the configuration
    ```bash
    envoy -c envoy-config.yaml
    ```

1. Keep both terminals open to observe the log and in the
    third terminal run the request

    ```bash
    cd client
    go run client.go
    ```

    The Envoy should log information about detected XSS Attack.

    The Flask server should not log anything as the request
    should not reach it (although something may reach the server
    as the payload is being sent to the upstream as the envoy
    may not complete the scanning before payload chunks reach
    the upstream - this is another issue)/

1. Now run again in the third terminal the client.go again but
    this time with request trailer

    ```bash
    go run client.go -a
    ```

    This time, the XSS Attack will be detected by the Envoy after
    2 seconds, after the Flask server returned the response.

### After the fix

Now build the WASM binary with the fix applied and redo the steps.

This time, the behaviour should not change for requests with trailers
and for requests with no trailers.
