module github.com/wasilibs/go-aho-corasick

go 1.20

// TIGERA FORK: versions aligned to gateway/coraza-wasm/go.mod's already-present
// indirect requires so the local `replace` adds no new go.sum entries. These deps
// back only the wazero (non-tinygo) path, which this vendored fork does not build.
require (
	github.com/magefile/mage v1.15.1-0.20241126214340-bdc92f694516
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20240411101913-e07a1f0e8eb4
	github.com/tetratelabs/wazero v1.7.2
)
