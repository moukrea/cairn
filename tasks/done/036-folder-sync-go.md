# Task 036: Folder-Sync Go Implementation

## Status
done

## Dependencies
- None

## Spec References
- spec/08-demo-folder-sync-expansion.md

## Scope
Implement the Go folder-sync demo at `demo/folder-sync/go/`. This ports the existing Rust/TypeScript folder-sync logic to Go, using the cairn-p2p Go library. The implementation includes CLI parsing, file watching, manifest comparison, chunked transfer, delta sync, and conflict resolution.

## Acceptance Criteria
- [x] `demo/folder-sync/go/main.go` exists as the entry point with CLI flag parsing
- [x] `demo/folder-sync/go/go.mod` and `go.sum` declare dependencies (cairn-p2p, fsnotify)
- [x] All CLI flags supported: `--dir`, `--pair-pin`, `--enter-pin`, `--pair-qr`, `--scan-qr`, `--pair-link`, `--from-link`, `--mesh`, `--server-hub`, `--signal`, `--turn`, `--verbose`
- [x] Sync protocol implemented: file watching, SHA-256 manifest comparison, 64KB chunked transfer, delta sync, `.conflict-{timestamp}` conflict resolution
- [x] `--help` flag prints usage information
- [x] Code compiles without errors: `cd demo/folder-sync/go && go build ./...`
- [x] Uses same API patterns as `demo/messaging/go/`

## Implementation Notes
Port logic from existing Rust (`demo/folder-sync/rust/src/main.rs`, `sync.rs`) and TypeScript (`demo/folder-sync/typescript/src/index.ts`, `sync.ts`) implementations.

Dependencies:
- P2P library: `github.com/moukrea/cairn/packages/go/cairn-p2p`
- CLI parsing: standard `flag` package
- File watching: `github.com/fsnotify/fsnotify`

Use goroutines for concurrent file watching and P2P communication. Follow the same API patterns shown in `demo/messaging/go/`.

Key sync protocol details:
- Monitor `--dir` directory for create, modify, delete, rename events
- Compute SHA-256 hash of each file for manifest comparison
- Transfer changed files in 64KB chunks over cairn P2P session
- Only send changed chunks (delta sync) by comparing chunk hashes
- On simultaneous edit conflict, rename incoming file with `.conflict-{timestamp}` suffix

## Files to Create or Modify
- `demo/folder-sync/go/main.go` (new)
- `demo/folder-sync/go/sync.go` (new)
- `demo/folder-sync/go/go.mod` (new)

## Verification Commands
- `cd demo/folder-sync/go && go build ./...`
- `cd demo/folder-sync/go && go vet ./...`
- `cd demo/folder-sync/go && go run . --help`
