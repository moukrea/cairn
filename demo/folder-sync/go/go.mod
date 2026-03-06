module github.com/moukrea/cairn/demo/folder-sync/go

go 1.24.0

require (
	github.com/fsnotify/fsnotify v1.8.0
	github.com/moukrea/cairn/packages/go/cairn-p2p v0.0.0
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/moukrea/cairn/packages/go/cairn-p2p => ../../../packages/go/cairn-p2p
