.PHONY: build
build:
	mkdir -p ./build
	tinygo build -o build/main.wasm -scheduler=asyncify -target=wasi ./main.go

test:
	go test -tags=proxytest ./...