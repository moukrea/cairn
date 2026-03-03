<?php

declare(strict_types=1);

namespace Cairn\Transport;

use React\Promise\PromiseInterface;

/**
 * A single connection to a remote peer over a transport.
 */
interface ConnectionInterface
{
    /**
     * Send data to the remote peer.
     *
     * @param string $data Raw bytes to send
     * @return PromiseInterface<void>
     */
    public function send(string $data): PromiseInterface;

    /**
     * Register a callback for received data.
     *
     * @param callable(string): void $onData Called with raw bytes when data arrives
     */
    public function onData(callable $onData): void;

    /**
     * Register a callback for connection close.
     *
     * @param callable(): void $onClose Called when the connection is closed
     */
    public function onClose(callable $onClose): void;

    /**
     * Close this connection.
     *
     * @return PromiseInterface<void>
     */
    public function close(): PromiseInterface;

    /**
     * Get the remote address.
     */
    public function remoteAddress(): string;

    /**
     * Get the local address.
     */
    public function localAddress(): string;
}
