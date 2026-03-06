---
sidebar_position: 1
title: "Messaging Demo"
---

# Messaging Demo

Interactive P2P encrypted chat between two peers. Available in all 5 languages (Rust, TypeScript, Go, Python, PHP).

## What the Demo Does

Two peers connect via PIN pairing and exchange real-time encrypted messages. The demo showcases:
- Node creation and identity generation
- PIN, QR code, and link pairing
- Bidirectional encrypted messaging
- Optional signaling and relay server integration

## Running with Docker

Each language has its own Docker image:

```bash
# Rust
docker run -it ghcr.io/moukrea/cairn-demo-messaging-rust --pair-pin

# TypeScript
docker run -it ghcr.io/moukrea/cairn-demo-messaging-ts --pair-pin

# Go
docker run -it ghcr.io/moukrea/cairn-demo-messaging-go --pair-pin

# Python
docker run -it ghcr.io/moukrea/cairn-demo-messaging-py --pair-pin

# PHP
docker run -it ghcr.io/moukrea/cairn-demo-messaging-php --pair-pin
```

On the second terminal, enter the PIN displayed by the first peer:

```bash
docker run -it ghcr.io/moukrea/cairn-demo-messaging-rust --enter-pin A1B2-C3D4
```

## Running with Docker Compose

### Basic (Tier 0)

No infrastructure required -- peers discover each other directly:

```bash
docker compose up peer-a peer-b
```

### With Infrastructure (Tier 1)

Add signaling and relay servers for faster discovery and NAT traversal:

```bash
docker compose --profile infra up
```

## CLI Flags

| Flag                    | Description                                      |
|-------------------------|--------------------------------------------------|
| `--pair-pin`            | Generate and display a PIN for pairing           |
| `--enter-pin XXXX-XXXX` | Enter a PIN from the initiator                  |
| `--pair-qr`             | Generate a QR code for pairing                  |
| `--scan-qr <data>`      | Scan QR code data from the initiator            |
| `--pair-link`           | Generate a pairing link URI                      |
| `--from-link <uri>`     | Accept a pairing link from the initiator        |
| `--signal <url>`        | Connect to a custom signaling server             |
| `--turn <url>`          | Connect to a custom TURN relay server            |
| `--verbose`             | Enable verbose logging                           |

## Interactive Commands

Once connected, type messages and press Enter to send. Special commands:

| Command    | Description            |
|------------|------------------------|
| `/status`  | Show connection status |
| `/quit`    | Exit the application   |

## Connecting to Custom Servers

Pass `--signal` and `--turn` flags to connect through your own infrastructure:

```bash
docker run -it ghcr.io/moukrea/cairn-demo-messaging-rust \
  --signal wss://signal.example.com \
  --turn turn:relay.example.com:3478 \
  --pair-pin
```
