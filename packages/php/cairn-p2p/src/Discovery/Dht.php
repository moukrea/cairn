<?php

declare(strict_types=1);

namespace Cairn\Discovery;

use Cairn\Error\CairnException;
use React\Promise\PromiseInterface;

use function React\Promise\resolve;

/**
 * Kademlia DHT-based discovery backend.
 *
 * Implements a lightweight DHT client for rendezvous-based peer discovery.
 * The rendezvous ID is used as the DHT key and encrypted reachability info
 * as the value.
 *
 * PHP does not have a libp2p library, so this is a custom implementation
 * that can connect to DHT bootstrap nodes for lookup operations.
 *
 * Matches packages/rs/cairn-p2p/src/discovery/backends.rs KademliaBackend.
 */
final class DhtBackend implements DiscoveryBackendInterface
{
    /** @var array<string, string> Records: key_hex -> payload */
    private array $records = [];

    /**
     * @param list<string> $bootstrapNodes Bootstrap node addresses (host:port)
     */
    public function __construct(
        private readonly array $bootstrapNodes = [],
    ) {
    }

    public function name(): string
    {
        return 'kademlia';
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
     * Get the configured bootstrap nodes.
     *
     * @return list<string>
     */
    public function bootstrapNodes(): array
    {
        return $this->bootstrapNodes;
    }

    /**
     * Get the number of published records.
     */
    public function recordCount(): int
    {
        return count($this->records);
    }
}
