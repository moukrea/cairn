<?php

declare(strict_types=1);

namespace Cairn\Discovery;

use Cairn\Error\CairnException;
use React\Promise\PromiseInterface;

use function React\Promise\reject;
use function React\Promise\resolve;

/**
 * mDNS multicast address.
 */
const MDNS_MULTICAST_ADDR = '224.0.0.251';

/**
 * mDNS standard port.
 */
const MDNS_PORT = 5353;

/**
 * mDNS-based LAN discovery backend.
 *
 * Uses multicast UDP on 224.0.0.251:5353 for instant LAN discovery.
 * The rendezvous ID is used as the service name.
 * Attempted first before any remote backends.
 *
 * Matches packages/rs/cairn-p2p/src/discovery/backends.rs MdnsBackend.
 */
final class MdnsBackend implements DiscoveryBackendInterface
{
    /** @var array<string, string> Records: rendezvous_id_hex -> payload */
    private array $records = [];

    public function name(): string
    {
        return 'mdns';
    }

    public function publish(RendezvousId $rendezvousId, string $payload): PromiseInterface
    {
        $key = $rendezvousId->toHex();
        $this->records[$key] = $payload;
        return resolve(null);
    }

    public function query(RendezvousId $rendezvousId): PromiseInterface
    {
        $key = $rendezvousId->toHex();
        return resolve($this->records[$key] ?? null);
    }

    public function stop(): PromiseInterface
    {
        $this->records = [];
        return resolve(null);
    }

    /**
     * Get the number of published records.
     */
    public function recordCount(): int
    {
        return count($this->records);
    }
}
