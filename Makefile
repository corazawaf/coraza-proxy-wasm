ARTIFACT_NAME="coraza-wasm-filter"
IMAGE_NAME=$(ARTIFACT_NAME):latest
CONTAINER_NAME=$(ARTIFACT_NAME)-build

.PHONY: build
build:
	mkdir -p ./build
	tinygo build -o build/main.wasm -scheduler=none -target=wasi ./main.go

test:
	go test -tags="proxytest tinygo" ./...

server-test-build:
	docker build --progress=plain -t $(IMAGE_NAME) -f Dockerfile.server-test .

server-test-wasm-dump: server-test-build
	@docker rm -f $(CONTAINER_NAME) || true
	@docker create -ti --name $(CONTAINER_NAME) $(IMAGE_NAME) bash
	docker cp $(CONTAINER_NAME):/usr/bin/wasm-filter/build ./
	@docker rm -f $(CONTAINER_NAME)

server-test-run: server-test-build
	docker run -p 8001:8001 $(IMAGE_NAME)