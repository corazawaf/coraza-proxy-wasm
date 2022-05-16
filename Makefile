.PHONY: build
build:
	mkdir -p ./build
	tinygo build -o build/main.wasm -scheduler=none -target=wasi ./main.go

test:
	go test -tags=proxytest ./...