ARTIFACT_NAME="coraza-wasm-filter"
IMAGE_NAME=$(ARTIFACT_NAME):latest
CONTAINER_NAME=$(ARTIFACT_NAME)-build

.PHONY: build
build:
	mkdir -p ./build
	tinygo build -o build/mainraw.wasm -scheduler=none -target=wasi ./main.go
# Removes unused code, which is important since compiled unused code may import unavailable host functions
	wasm-opt -Os -c build/mainraw.wasm -o build/mainopt.wasm
# Unfortuantely the imports themselves are left due to potential use with call_indirect. Hack away missing functions
# until they are stubbed in Envoy because we know we don't need them.
	wasm2wat build/mainopt.wasm -o build/mainopt.wat
	sed 's/fd_filestat_get/fd_fdstat_get/g' build/mainopt.wat | sed 's/"wasi_snapshot_preview1" "path_filestat_get"/"env" "proxy_get_header_map_value"/g' > build/main.wat
	wat2wasm build/main.wat -o build/main.wasm

test:
	go test -tags="proxytest" ./...
