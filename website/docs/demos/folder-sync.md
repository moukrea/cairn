---
sidebar_position: 2
title: "Folder Sync Demo"
---

# Folder Sync Demo

Real-time P2P file synchronization between two directories. Changes in one directory are automatically propagated to the other, encrypted end-to-end.

## What the Demo Does

Two peers pair and continuously sync the contents of a local directory. When a file is created, modified, or deleted on one side, the change is replicated to the other. Available in Go, Python, and PHP.

## Running with Docker

Mount a local directory into the container:

```bash
# Peer A (initiator)
docker run -it \
  -v ./my-files:/sync \
  ghcr.io/moukrea/cairn-demo-folder-sync-go \
  --dir /sync --pair-pin

# Peer B (responder) -- in another terminal
docker run -it \
  -v ./other-files:/sync \
  ghcr.io/moukrea/cairn-demo-folder-sync-go \
  --dir /sync --enter-pin A1B2-C3D4
```

Language variants: `-go`, `-py`, `-php`.

## Running with Docker Compose

```bash
docker compose up peer-a peer-b
```

By default, `./sync-a` and `./sync-b` on the host are mounted as the sync directories. Files placed in `sync-a/` appear in `sync-b/` and vice versa.

## CLI Flags

| Flag                    | Description                                      |
|-------------------------|--------------------------------------------------|
| `--dir <path>`          | Directory to synchronize                         |
| `--pair-pin`            | Generate and display a PIN for pairing           |
| `--enter-pin XXXX-XXXX` | Enter a PIN from the initiator                  |
| `--pair-qr`             | Generate a QR code for pairing                  |
| `--scan-qr <data>`      | Scan QR code data from the initiator            |
| `--pair-link`           | Generate a pairing link URI                      |
| `--from-link <uri>`     | Accept a pairing link from the initiator        |
| `--mesh`                | Enable mesh routing for multi-device sync        |
| `--server-hub`          | Run as a server hub for store-and-forward        |
| `--signal <url>`        | Connect to a custom signaling server             |
| `--turn <url>`          | Connect to a custom TURN relay server            |
| `--verbose`             | Enable verbose logging                           |

## Mesh Sync with 3+ Devices

Use the `--mesh` flag to enable multi-device synchronization. Any device can sync with any other, even if they cannot connect directly:

```bash
# Device A (hub -- always on)
docker run -it -v ./hub-sync:/sync \
  ghcr.io/moukrea/cairn-demo-folder-sync-go \
  --dir /sync --mesh --server-hub --pair-pin

# Device B
docker run -it -v ./device-b-sync:/sync \
  ghcr.io/moukrea/cairn-demo-folder-sync-go \
  --dir /sync --mesh --enter-pin <PIN-from-A>

# Device C
docker run -it -v ./device-c-sync:/sync \
  ghcr.io/moukrea/cairn-demo-folder-sync-go \
  --dir /sync --mesh --enter-pin <PIN-from-A>
```

Devices B and C sync through the hub even if they cannot reach each other directly. All traffic is end-to-end encrypted -- the hub forwards ciphertext only.
