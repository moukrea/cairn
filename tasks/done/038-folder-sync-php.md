# Task 038: Folder-Sync PHP Implementation

## Status
done

## Dependencies
- None

## Spec References
- spec/08-demo-folder-sync-expansion.md

## Scope
Implement the PHP folder-sync demo at `demo/folder-sync/php/`. This ports the existing Rust/TypeScript folder-sync logic to PHP, using the cairn-p2p PHP library with inotify or polling-based file watching.

## Acceptance Criteria
- [ ] `demo/folder-sync/php/cairn_sync.php` exists as the entry point
- [ ] `demo/folder-sync/php/composer.json` declares dependencies (moukrea/cairn-p2p)
- [ ] All CLI flags supported: `--dir`, `--pair-pin`, `--enter-pin`, `--pair-qr`, `--scan-qr`, `--pair-link`, `--from-link`, `--mesh`, `--server-hub`, `--signal`, `--turn`, `--verbose`
- [ ] Sync protocol implemented: file watching, SHA-256 manifest comparison, 64KB chunked transfer, delta sync, `.conflict-{timestamp}` conflict resolution
- [ ] `--help` flag prints usage information
- [ ] Code runs without errors: `cd demo/folder-sync/php && php cairn_sync.php --help`
- [ ] Uses same API patterns as `demo/messaging/php/`

## Implementation Notes
Port logic from existing Rust (`demo/folder-sync/rust/src/main.rs`, `sync.rs`) and TypeScript (`demo/folder-sync/typescript/src/index.ts`, `sync.ts`) implementations.

Dependencies:
- P2P library: `moukrea/cairn-p2p` (Packagist)
- CLI parsing: `getopt()` (built-in) or `symfony/console`
- File watching: `inotify` extension, with polling fallback

If `inotify` extension is not available, fall back to polling-based file change detection. Follow the same API patterns shown in `demo/messaging/php/`.

Key sync protocol details:
- Monitor `--dir` directory for create, modify, delete, rename events
- Compute SHA-256 hash of each file for manifest comparison
- Transfer changed files in 64KB chunks over cairn P2P session
- Only send changed chunks (delta sync) by comparing chunk hashes
- On simultaneous edit conflict, rename incoming file with `.conflict-{timestamp}` suffix

## Files to Create or Modify
- `demo/folder-sync/php/cairn_sync.php` (new)
- `demo/folder-sync/php/composer.json` (new)

## Verification Commands
- `cd demo/folder-sync/php && php cairn_sync.php --help`
