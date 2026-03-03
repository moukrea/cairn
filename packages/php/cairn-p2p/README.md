# cairn-p2p

PHP implementation of the cairn P2P connectivity library.

## Installation

```bash
composer require moukrea/cairn-p2p
```

## Requirements

- PHP 8.2+
- Extensions: sodium, openssl, gmp
- ReactPHP event loop for long-running daemon operation

## Quick Start

```php
<?php
use Cairn\CairnNode;
use React\EventLoop\Loop;

$loop = Loop::get();
$node = CairnNode::create($loop);
$peer = $node->pairWithPin('123456');
$peer->send('hello');
$loop->run();
```

## API Overview

- `CairnNode` -- Main entry point, manages identity, sessions, and discovery
- `Session` -- Persistent encrypted session with a peer
- `PeerIdentity` -- Ed25519 identity with Peer ID derivation
- `CairnConfig` -- Configuration with tier presets

## Key Dependencies

- `ext-sodium` -- ChaCha20-Poly1305, X25519, Ristretto255
- `ext-openssl` -- AES-256-GCM
- `react/event-loop` -- Async event loop
- `react/socket` -- TCP transport
- `ramsey/uuid` -- UUID v7 generation
- `endroid/qr-code` -- QR code pairing

## Note on PHP

PHP's request/response execution model requires a long-running daemon process (via ReactPHP) for persistent P2P connections. The event loop must be running for transport I/O, heartbeat timers, and reconnection to function.

## License

Licensed under the [MIT License](../../../LICENSE).
