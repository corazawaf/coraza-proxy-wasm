# Kong example

## Getting started

```shell
METRICS=off mage build
```

In `example/kong` folder:

```shell
docker-compose up
```

In `e2e`:

```shell
ENVOY_HOST=localhost:8000 HTTPBIN_HOST=localhost:8080 ./e2e-example.sh
```
