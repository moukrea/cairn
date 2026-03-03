<?php

declare(strict_types=1);

namespace Cairn\Transport;

use React\Promise\PromiseInterface;

/**
 * Transport abstraction for cairn peer connectivity.
 *
 * All methods return ReactPHP promises for async I/O.
 * Implementations: TCP, WebSocket, STUN UDP hole punch, etc.
 */
interface TransportInterface
{
    /**
     * Connect to a remote peer.
     *
     * @param string $address The remote address (host:port or URI)
     * @param float $timeout Connection timeout in seconds
     * @return PromiseInterface<ConnectionInterface> Resolves with the connection
     */
    public function connect(string $address, float $timeout = 10.0): PromiseInterface;

    /**
     * Listen for incoming connections.
     *
     * @param string $address The local address to bind to (host:port)
     * @param callable(ConnectionInterface): void $onConnection Callback for new connections
     */
    public function listen(string $address, callable $onConnection): void;

    /**
     * Close the transport and release resources.
     *
     * @return PromiseInterface<void>
     */
    public function close(): PromiseInterface;

    /**
     * Get the transport type identifier.
     */
    public function type(): TransportType;

    /**
     * Whether this transport is currently active/connected.
     */
    public function isActive(): bool;
}
