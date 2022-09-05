- 00-modsecurity.conf: `SecRequestBodyJsonDepthLimit` not supported
- 00-modsecurity.conf: `SecAuditLogRelevantStatus` uses syntax not supported with re2
- 00-modsecurity.conf: `SecStatusEngine` not supported
- REQUEST-912-DOS-PROTECTION: 912171 temporarily disabled since doesn't interact well with go-ftw
- REQUEST-920-PROTOCOL-ENFORCEMENT: 920120 not supported with re2
- REQUEST-920-PROTOCOL-ENFORCEMENT: 920250 temporarily disabled since doesn't interact well with go-ftw
- REQUEST-920-PROTOCOL-ENFORCEMENT: 920350 updated regex to latest CRS version
- REQUEST-942-APPLICATION-ATTACK-SQLI: 942130: not supported with re2
- REQUEST-942-APPLICATION-ATTACK-SQLI: 942480: regexp fails to compile in wasm with "out of bounds memory access"
- RESPONSE-953-DATA-LEAKAGES-PHP: 953120: not supported with re2
- RESPONSE-954-DATA-LEAKAGES-IIS: 954110: regexp fails to compile in wasm with "out of bounds memory access"
- RESPONSE-954-DATA-LEAKAGES-IIS: 954120: regexp fails to compile in wasm with "out of bounds memory access"
- RESPONSE-954-DATA-LEAKAGES-IIS: 954130: regexp fails to compile in wasm with "out of bounds memory access"

Note, it still needs to be investigated whether "out of bounds memory access" only happens with wazero (used in tests)
and not when run under Envoy.