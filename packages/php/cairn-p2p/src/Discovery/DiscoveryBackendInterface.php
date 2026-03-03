<?php

declare(strict_types=1);

namespace Cairn\Discovery;

use React\Promise\PromiseInterface;

/**
 * A pluggable discovery backend interface.
 *
 * Backends implement peer discovery over different infrastructure:
 * mDNS for LAN, Kademlia DHT, BitTorrent trackers, signaling servers.
 *
 * Matches packages/rs/cairn-p2p/src/discovery/backends.rs DiscoveryBackend.
 */
interface DiscoveryBackendInterface
{
    /**
     * Human-readable name for this backend.
     */
    public function name(): string;

    /**
     * Publish reachability information at the given rendezvous ID.
     *
     * @return PromiseInterface<null>
     */
    public function publish(RendezvousId $rendezvousId, string $payload): PromiseInterface;

    /**
     * Query for a peer's reachability at the given rendezvous ID.
     *
     * @return PromiseInterface<string|null>
     */
    public function query(RendezvousId $rendezvousId): PromiseInterface;

    /**
     * Stop publishing and querying. Clean up resources.
     *
     * @return PromiseInterface<null>
     */
    public function stop(): PromiseInterface;
}
