#!/bin/bash

APP_NAME=coraza-proxy-wasm-kong
DOCKER_NETWORK=$(APP_NAME)-net
UPSTREAM_CONTAINER_NAME=$(APP_NAME)-upstream
UPSTREAM_HOST=upstream

run: launch-kong register-upstream

launch-kong:
	mkdir -p ./build
	cp $$(dirname $$(dirname $$(pwd)))/build/main.wasm ./build/coraza-proxy-wasm.wasm
	curl -Ls https://get.konghq.com/quickstart | bash -s -- -a $(APP_NAME) -i incubator -t gateway-wasmer-3.0.0.0 \
  		-e "KONG_LOG_LEVEL=debug" -e "KONG_WASM=on" -e "KONG_WASM_MODULES=/wasm/coraza-proxy-wasm.wasm" -v $$(pwd)/build:/wasm

register-upstream:
	@docker rm -f $(UPSTREAM_CONTAINER_NAME) || true
	docker run --name=$(UPSTREAM_CONTAINER_NAME) --network=$(DOCKER_NETWORK) --network-alias=$(UPSTREAM_HOST) -p "10080:10080" -d jcchavezs/httpmole -response-status=201
	http POST :8001/services/ name="upstream" host="$(UPSTREAM_HOST)" path="/" port:=10080 protocol="http"
	http POST :8001/services/upstream/routes name="upstream" "paths[]=/" "paths[]=/admin"
	http POST :8001/services/upstream/plugins name="proxy-wasm" \
		"config[filters][0][name]=coraza-proxy-wasm" \
		"config[filters][0][config]={\"rules\":[\"Include @demo-conf\",\"Include @crs-setup-demo-conf\",\"SecDebugLogLevel 3\",\"Include @owasp_crs/*.conf\",\"SecRule REQUEST_URI \\\"@streq /admin\\\" \\\"id:101,phase:1,t:lowercase,deny\\\" \\\nSecRule REQUEST_BODY \\\"@rx maliciouspayload\\\" \\\"id:102,phase:2,t:lowercase,deny\\\" \\\nSecRule RESPONSE_HEADERS::status \\\"@rx 406\\\" \\\"id:103,phase:3,t:lowercase,deny\\\" \\\nSecRule RESPONSE_BODY \\\"@contains responsebodycode\\\" \\\"id:104,phase:4,t:lowercase,deny\\\"\"]}"

logs:
	docker logs -f coraza-proxy-wasm-kong-gateway

clean:
	@docker rm -f $(UPSTREAM_CONTAINER_NAME) || true
	curl -Ls https://get.konghq.com/quickstart | bash -s -- -a $(APP_NAME) -d
