- REQUEST-934-APPLICATION-ATTACK-GENERIC.conf: 934120: regexp fails to compile in wasm with "out of bounds memory access"
- REQUEST-942-APPLICATION-ATTACK-SQLI: 942480: regexp fails to compile in wasm with "out of bounds memory access" 
- RESPONSE-954-DATA-LEAKAGES-IIS: 954110: regexp fails to compile in wasm with "out of bounds memory access" 
- RESPONSE-954-DATA-LEAKAGES-IIS: 954120: regexp fails to compile in wasm with "out of bounds memory access"
- RESPONSE-954-DATA-LEAKAGES-IIS: 954130: regexp fails to compile in wasm with "out of bounds memory access"

Note, it still needs to be investigated whether "out of bounds memory access" only happens with wazero (used in tests)
and not when run under Envoy.