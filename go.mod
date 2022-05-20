module github.com/jcchavezs/coraza-wasm-filter

go 1.17

require (
	github.com/corazawaf/coraza/v2 v2.0.0
	github.com/stretchr/testify v1.7.1
	github.com/tetratelabs/proxy-wasm-go-sdk v0.18.1-0.20220510133519-6240ca761207
	github.com/tidwall/gjson v1.14.1
)

require (
	github.com/cloudflare/ahocorasick v0.0.0-20210425175752-730270c3e184 // indirect
	github.com/corazawaf/libinjection-go v0.0.0-20220207031228-44e9c4250eb5 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	golang.org/x/net v0.0.0-20220325170049-de3da57026de // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace github.com/corazawaf/coraza/v2 v2.0.0 => ./coraza
