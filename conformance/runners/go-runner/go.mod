module github.com/moukrea/cairn/conformance/runners/go-runner

go 1.25.0

require (
	github.com/fxamacker/cbor/v2 v2.9.0
	github.com/moukrea/cairn/packages/go/cairn-p2p v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
)

replace github.com/moukrea/cairn/packages/go/cairn-p2p => ../../../packages/go/cairn-p2p
