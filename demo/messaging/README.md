# P2P Messaging Demo

Interactive peer-to-peer chat application demonstrating cairn's pairing, encrypted sessions, and presence channels.

## Features Exercised

- QR code, PIN code, and pairing link mechanisms
- Noise XX handshake with mutual authentication
- Double ratchet encrypted sessions
- Chat and presence channels (typing indicators)
- Server-mode peer operation
- Store-and-forward offline message delivery
- NAT traversal via signaling and TURN relay

## Implementations

| Language   | Directory    |
|------------|--------------|
| Rust       | `rust/`      |
| TypeScript | `typescript/`|
| Go         | `go/`        |
| Python     | `python/`    |
| PHP        | `php/`       |

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

Start two terminals to simulate a peer-to-peer conversation.

**Terminal 1 (initiator):**

```bash
# Generate a PIN code for pairing
./target/release/cairn-chat --pair-pin
```

**Terminal 2 (responder):**

```bash
# Enter the PIN displayed by the initiator
./target/release/cairn-chat --enter-pin XXXX-XXXX
```

### Other pairing methods

```bash
# QR code pairing
cairn-chat --pair-qr          # initiator: displays QR data
cairn-chat --scan-qr <data>   # responder: scans QR data

# Pairing link
cairn-chat --pair-link         # initiator: displays URI
cairn-chat --from-link <uri>   # responder: accepts URI
```

### Server mode and store-and-forward

```bash
# Start as server-mode peer
cairn-chat --server-mode --pair-pin

# Send a message to an offline peer via server relay
cairn-chat --send "hello" --peer <id> --forward
```

### Additional flags

```bash
# Specify infrastructure servers
cairn-chat --signal wss://signal.example.com --turn turn:relay.example.com:3478

# Enable structured logging
cairn-chat --verbose
```

## Expected Output

```
cairn-chat started. Peer ID: 12D3KooW...
Generating PIN code...
PIN: A1B2-C3D4
Paired with: 12D3KooW...
Session established.
[online] peer> hello
you: hello
peer: hi there
--- Connection state: reconnecting ---
--- Connection state: connected ---
```

## Interactive Commands

- Type a message and press Enter to send
- `/status` -- show peer ID and connection state
- `/quit` or `/exit` -- close the session

## Known Limitations

- Presence indicators (typing, online/offline) are partially implemented -- the presence channel is opened but indicator display is basic
- QR code rendering to terminal is not implemented; QR data is printed as a string
