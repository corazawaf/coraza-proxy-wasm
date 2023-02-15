#!/bin/bash

UPSTREAM_HOST=${UPSTREAM_HOST:-httpbin}
KONG_HOST=${KONG_HOST:-kong}
KONG_HOSTPORT=${KONG_HOST}:8001

http --ignore-stdin POST ${KONG_HOSTPORT}/services name="httpbin" host="${UPSTREAM_HOST}" path="/" port:=10080 protocol="http"

http --ignore-stdin POST ${KONG_HOSTPORT}/services/httpbin/routes name="httpbin" "paths[]=/" "paths[]=/anything" "paths[]=/uuid"

http --ignore-stdin POST ${KONG_HOSTPORT}/services/httpbin/plugins name="proxy-wasm" \
    "config[filters][0][name]=main" \
    "config[filters][0][config]={\"rules\":[\"Include @demo-conf\",\"Include @crs-setup-demo-conf\",\"SecDebugLogLevel 3\",\"Include @owasp_crs/*.conf\",\"SecRule REQUEST_URI \\\"@streq /uuid\\\" \\\"id:101,phase:1,t:lowercase,deny\\\" \\\nSecRule REQUEST_BODY \\\"@rx maliciouspayload\\\" \\\"id:102,phase:2,t:lowercase,deny\\\" \\\nSecRule RESPONSE_HEADERS::status \\\"@rx 406\\\" \\\"id:103,phase:3,t:lowercase,deny\\\" \\\nSecRule RESPONSE_BODY \\\"@contains responsebodycode\\\" \\\"id:104,phase:4,t:lowercase,deny\\\"\"]}"

http --ignore-stdin GET ${KONG_HOST}:8000/