module github.com/wasilibs/go-libinjection

go 1.20

// TIGERA FORK: versions aligned to gateway/coraza-wasm/go.mod's already-present
// indirect requires so the local `replace` adds no new go.sum entries. These deps
// back only the wazero (non-tinygo) path, which this vendored fork does not build.
require (
	github.com/corazawaf/libinjection-go v0.2.2
	github.com/magefile/mage v1.15.1-0.20241126214340-bdc92f694516
	github.com/tetratelabs/wazero v1.7.2
)
