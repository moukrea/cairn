# P2P Folder Sync Demo

Peer-to-peer folder synchronization demonstrating cairn's encrypted channels, chunked file transfer, conflict resolution, and mesh routing.

## Features Exercised

- QR code, PIN code, and pairing link mechanisms
- Encrypted sync channel over double ratchet sessions
- Chunked file transfer (64 KB chunks)
- Delta sync for efficient updates
- File conflict detection and resolution (rename-based)
- Mesh routing for multi-device sync
- Server-mode sync hub

## Implementations

| Language   | Directory    |
|------------|--------------|
| Rust       | `rust/`      |
| TypeScript | `typescript/`|

## Prerequisites

### Rust

- Rust 1.75+
- `cargo` build tool

## Build (Rust)

```bash
cd rust
cargo build --release
```

## Run

Start two terminals, each watching a different directory.

**Terminal 1 (initiator):**

```bash
./target/release/cairn-folder-sync --dir ./sync-a --pair-pin
```

**Terminal 2 (responder):**

```bash
./target/release/cairn-folder-sync --dir ./sync-b --enter-pin XXXX-XXXX
```

Files created or modified in `sync-a` will be transferred to `sync-b` and vice versa.

### Mesh multi-device sync

```bash
# Enable mesh routing for 3+ device sync
cairn-folder-sync --dir ./sync-folder --pair-pin --mesh
```

### Server-mode sync hub

```bash
# Run as always-on hub that other devices sync through
cairn-folder-sync --dir ./sync-hub --server-hub
```

### Additional flags

```bash
# Enable structured logging
cairn-folder-sync --verbose
```

## Expected Output

```
cairn-folder-sync started. Watching: /home/user/sync-a
Generating PIN code...
PIN: A1B2-C3D4
Paired with: 12D3KooW...
Sync session established.
Found 3 files to sync
[sync] Received metadata: notes.txt (1024 bytes)
[sync] Completed: notes.txt
[conflict] report.pdf — preserved as report.12D3Ko.20240101T120000.pdf
Watching for changes... (Ctrl+C to stop)
```

## Known Limitations

- Mesh routing and delta sync are basic implementations -- delta sync sends full chunks rather than binary diffs
- File watching is event-driven on the receiving side only; the sender performs an initial scan but does not watch for live filesystem changes
- Conflict resolution uses rename-based strategy (no interactive merge)
