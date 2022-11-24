#!/bin/sh
# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

cd /workspace

# Copied from https://github.com/jcchavezs/modsecurity-wasm-filter-e2e/blob/master/tests.sh

step=1
total_steps=1
max_retries=15 #seconds for the server reachability timeout
host=${1:-envoy}
health_url="http://${host}:80"
unfiltered_url="http://${host}:80/home"
filtered_url="http://${host}:80/admin"

# Testing if the server is up
echo "[$step/$total_steps] Testing application reachability"
status_code="000"
while [[ "$status_code" -eq "000" ]]; do
  status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null $health_url)
  sleep 1
  echo -ne "[Wait] Waiting for response from $health_url. Timeout: ${max_retries}s   \r"
  let "max_retries--"
  if [[ "$max_retries" -eq 0 ]] ; then
    echo "[Fail] Timeout waiting for response from $health_url, make sure the server is running."
    echo "Envoy Logs:" && cat /home/envoy/logs/envoy.log
    exit 1
  fi
done
echo -e "\n[Ok] Got status code $status_code, expected 200. Ready to start."

FTW_CLOUDMODE=${FTW_CLOUDMODE:-false}

/ftw run -d coreruleset/tests/regression/tests --config ftw.yml --read-timeout=10s --cloud=$FTW_CLOUDMODE || exit 1
