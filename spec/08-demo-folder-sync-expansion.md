# 08 — Demo Folder Sync Expansion (Go, Python, PHP)

## Cross-References

- **Depends on: `07-demo-dockerization.md`** — Each new implementation gets a corresponding Dockerfile defined there.

---

## 1. Overview

Three new folder-sync demo implementations must be created:

| Language | Entry Point | Dependency File |
|----------|-------------|-----------------|
| Go | `demo/folder-sync/go/main.go` | `go.mod` / `go.sum` |
| Python | `demo/folder-sync/python/cairn_sync.py` | `pyproject.toml` |
| PHP | `demo/folder-sync/php/cairn_sync.php` | `composer.json` |

All implementations must faithfully port the logic from the existing Rust (`demo/folder-sync/rust/src/main.rs`, `sync.rs`) and TypeScript (`demo/folder-sync/typescript/src/index.ts`, `sync.ts`) implementations.

---

## 2. CLI Interface (All Languages)

Every implementation must support the identical set of CLI flags:

| Flag | Description |
|------|-------------|
| `--dir <path>` | Directory to sync |
| `--pair-pin` | Initiator: display PIN |
| `--enter-pin XXXX-XXXX` | Responder: enter PIN |
| `--pair-qr` | Initiator: display QR code data |
| `--scan-qr` | Responder: scan QR code |
| `--pair-link` | Initiator: generate pairing link URI |
| `--from-link <uri>` | Responder: accept pairing link |
| `--mesh` | Enable mesh routing |
| `--server-hub` | Always-on sync hub mode |
| `--signal <url>` | Signaling server URL |
| `--turn <url>` | TURN relay URL |
| `--verbose` | Structured logging |

---

## 3. Sync Protocol

All implementations must match the existing Rust/TypeScript sync protocol exactly.

### 3.1 File Watching

- Monitor the sync directory (`--dir`) for file system changes
- Detect: create, modify, delete, rename

### 3.2 Manifest Comparison

- On change: compute SHA-256 hash of each file
- Compare local manifest with peer's manifest to determine which files need syncing

### 3.3 Chunked Transfer

- Transfer changed files in **64KB chunks**
- Stream chunks over the cairn P2P session

### 3.4 Delta Sync

- Only send changed chunks (not entire files)
- Compare chunk hashes to determine which 64KB blocks differ

### 3.5 Conflict Resolution

- When both peers modify the same file simultaneously, rename the conflicting file with a `.conflict-{timestamp}` suffix
- The peer that detects the conflict keeps its version and renames the incoming version

---

## 4. Go Implementation

### 4.1 Files

- `demo/folder-sync/go/main.go` — entry point and CLI parsing
- Additional files as needed for sync logic

### 4.2 Dependencies

- P2P library: `github.com/moukrea/cairn/packages/go/cairn-p2p`
- CLI parsing: standard `flag` package or equivalent
- File watching: use an appropriate Go file watcher library (e.g., `fsnotify`)

### 4.3 Implementation Notes

- Use the same API patterns shown in the Go messaging demo (`demo/messaging/go/`)
- Use goroutines for concurrent file watching and P2P communication

---

## 5. Python Implementation

### 5.1 Files

- `demo/folder-sync/python/cairn_sync.py` — entry point
- `demo/folder-sync/python/pyproject.toml` — dependencies

### 5.2 Dependencies

- P2P library: `cairn-p2p` (PyPI package)
- CLI parsing: `argparse` (stdlib)
- File watching: `watchdog`
- Async: `asyncio` (stdlib)

### 5.3 Implementation Notes

- Use `asyncio` for all async operations
- Use `watchdog` for file system event monitoring
- Use the same API patterns shown in the Python messaging demo (`demo/messaging/python/`)

---

## 6. PHP Implementation

### 6.1 Files

- `demo/folder-sync/php/cairn_sync.php` — entry point
- `demo/folder-sync/php/composer.json` — dependencies

### 6.2 Dependencies

- P2P library: `moukrea/cairn-p2p` (Packagist package)
- CLI parsing: `getopt()` (built-in) or `symfony/console`
- File watching: `inotify` extension or polling-based approach

### 6.3 Implementation Notes

- Use the same API patterns shown in the PHP messaging demo (`demo/messaging/php/`)
- If `inotify` extension is not available, fall back to polling-based file change detection

---

## 7. Implementation Approach

For all three new implementations:

1. Read the existing Rust (`demo/folder-sync/rust/src/main.rs`, `sync.rs`) and TypeScript (`demo/folder-sync/typescript/src/index.ts`, `sync.ts`) implementations
2. Port the logic faithfully -- same sync protocol, same CLI flags, same conflict resolution
3. Use the respective language's cairn-p2p library with the same API patterns shown in the messaging demo for that language

---

## 8. Testing

- Each new implementation must compile/run without errors
- Each implementation must support the `--help` flag and print usage information
- The sync protocol behavior must match the existing Rust/TypeScript implementations
