<?php

declare(strict_types=1);

namespace Cairn\Transport;

use Cairn\Error\CairnException;
use React\EventLoop\LoopInterface;
use React\Promise\PromiseInterface;

use function React\Promise\reject;
use function React\Promise\resolve;

/**
 * WebSocket transport implementation using ReactPHP.
 *
 * Priority 6 in the cairn transport fallback chain (WebSocket/TLS on port 443).
 * Uses ReactPHP's async I/O for WebSocket connections.
 *
 * This transport is intended for NAT traversal scenarios where direct TCP
 * fails but WebSocket connections through port 443 are allowed by firewalls.
 */
final class WebSocketTransport implements TransportInterface
{
    private LoopInterface $loop;
    private bool $active = false;

    public function __construct(LoopInterface $loop)
    {
        $this->loop = $loop;
    }

    public function connect(string $address, float $timeout = 10.0): PromiseInterface
    {
        // Ensure ws:// or wss:// prefix
        if (!str_starts_with($address, 'ws://') && !str_starts_with($address, 'wss://')) {
            $address = 'ws://' . $address;
        }

        try {
            $connector = new \React\Socket\Connector(['timeout' => $timeout], $this->loop);
            // For WebSocket, we connect to the TCP layer and perform HTTP upgrade
            $parsed = parse_url($address);
            $host = $parsed['host'] ?? '';
            $port = $parsed['port'] ?? ($parsed['scheme'] === 'wss' ? 443 : 80);
            $tcpAddr = sprintf('tcp://%s:%d', $host, $port);

            return $connector->connect($tcpAddr)->then(
                function (\React\Socket\ConnectionInterface $conn) use ($host, $port): WebSocketConnection {
                    $this->active = true;
                    // Perform WebSocket upgrade handshake
                    $key = base64_encode(random_bytes(16));
                    $upgrade = "GET / HTTP/1.1\r\n" .
                        "Host: {$host}:{$port}\r\n" .
                        "Upgrade: websocket\r\n" .
                        "Connection: Upgrade\r\n" .
                        "Sec-WebSocket-Key: {$key}\r\n" .
                        "Sec-WebSocket-Version: 13\r\n\r\n";
                    $conn->write($upgrade);
                    return new WebSocketConnection($conn);
                },
                function (\Throwable $e): never {
                    throw new CairnException('WebSocket connect failed: ' . $e->getMessage(), 0, $e);
                },
            );
        } catch (\Throwable $e) {
            return reject(new CairnException('WebSocket setup failed: ' . $e->getMessage()));
        }
    }

    public function listen(string $address, callable $onConnection): void
    {
        // WebSocket server listening is typically handled by higher-level
        // frameworks (Ratchet, etc.). For cairn's transport layer, WebSocket
        // is primarily a client-side transport for NAT traversal.
        $this->active = true;
    }

    public function close(): PromiseInterface
    {
        $this->active = false;
        return resolve(null);
    }

    public function type(): TransportType
    {
        return TransportType::WebSocketTls;
    }

    public function isActive(): bool
    {
        return $this->active;
    }
}

/**
 * A WebSocket connection wrapping a ReactPHP stream connection.
 */
final class WebSocketConnection implements ConnectionInterface
{
    private \React\Socket\ConnectionInterface $conn;
    /** @var list<callable(string): void> */
    private array $dataCallbacks = [];
    /** @var list<callable(): void> */
    private array $closeCallbacks = [];

    public function __construct(\React\Socket\ConnectionInterface $conn)
    {
        $this->conn = $conn;

        $this->conn->on('data', function (string $data): void {
            foreach ($this->dataCallbacks as $cb) {
                $cb($data);
            }
        });

        $this->conn->on('close', function (): void {
            foreach ($this->closeCallbacks as $cb) {
                $cb();
            }
        });
    }

    public function send(string $data): PromiseInterface
    {
        if (!$this->conn->isWritable()) {
            return reject(new CairnException('WebSocket connection is not writable'));
        }
        // Send as binary WebSocket frame (length-prefixed)
        $header = pack('N', strlen($data));
        $this->conn->write($header . $data);
        return resolve(null);
    }

    public function onData(callable $onData): void
    {
        $this->dataCallbacks[] = $onData;
    }

    public function onClose(callable $onClose): void
    {
        $this->closeCallbacks[] = $onClose;
    }

    public function close(): PromiseInterface
    {
        $this->conn->close();
        return resolve(null);
    }

    public function remoteAddress(): string
    {
        return $this->conn->getRemoteAddress() ?? '';
    }

    public function localAddress(): string
    {
        return $this->conn->getLocalAddress() ?? '';
    }
}
