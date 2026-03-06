# Task 037: Folder-Sync Python Implementation

## Status
done

## Dependencies
- None

## Spec References
- spec/08-demo-folder-sync-expansion.md

## Scope
Implement the Python folder-sync demo at `demo/folder-sync/python/`. This ports the existing Rust/TypeScript folder-sync logic to Python, using the cairn-p2p Python library with asyncio and watchdog for file system monitoring.

## Acceptance Criteria
- [ ] `demo/folder-sync/python/cairn_sync.py` exists as the entry point
- [ ] `demo/folder-sync/python/pyproject.toml` declares dependencies (cairn-p2p, watchdog)
- [ ] All CLI flags supported: `--dir`, `--pair-pin`, `--enter-pin`, `--pair-qr`, `--scan-qr`, `--pair-link`, `--from-link`, `--mesh`, `--server-hub`, `--signal`, `--turn`, `--verbose`
- [ ] Sync protocol implemented: file watching, SHA-256 manifest comparison, 64KB chunked transfer, delta sync, `.conflict-{timestamp}` conflict resolution
- [ ] `--help` flag prints usage information
- [ ] Code runs without import errors: `cd demo/folder-sync/python && python cairn_sync.py --help`
- [ ] Uses same API patterns as `demo/messaging/python/`

## Implementation Notes
Port logic from existing Rust (`demo/folder-sync/rust/src/main.rs`, `sync.rs`) and TypeScript (`demo/folder-sync/typescript/src/index.ts`, `sync.ts`) implementations.

Dependencies:
- P2P library: `cairn-p2p` (PyPI)
- CLI parsing: `argparse` (stdlib)
- File watching: `watchdog`
- Async: `asyncio` (stdlib)

Use `asyncio` for all async operations. Use `watchdog` for file system event monitoring. Follow the same API patterns shown in `demo/messaging/python/`.

Key sync protocol details:
- Monitor `--dir` directory for create, modify, delete, rename events
- Compute SHA-256 hash of each file for manifest comparison
- Transfer changed files in 64KB chunks over cairn P2P session
- Only send changed chunks (delta sync) by comparing chunk hashes
- On simultaneous edit conflict, rename incoming file with `.conflict-{timestamp}` suffix

## Files to Create or Modify
- `demo/folder-sync/python/cairn_sync.py` (new)
- `demo/folder-sync/python/pyproject.toml` (new)

## Verification Commands
- `cd demo/folder-sync/python && python cairn_sync.py --help`
