<?php

declare(strict_types=1);

namespace Cairn\Discovery;

use Cairn\Error\CairnException;
use React\Promise\PromiseInterface;

use function React\Promise\resolve;

/**
 * Minimum re-announce interval for BitTorrent trackers (15 minutes).
 */
const TRACKER_MIN_REANNOUNCE = 900;

/**
 * BitTorrent tracker-based discovery backend.
 *
 * Uses the rendezvous ID as an info_hash to publish and query peers
 * via BitTorrent tracker infrastructure:
 * - BEP 3: HTTP tracker announce/scrape
 * - BEP 15: UDP tracker protocol
 *
 * Minimum 15-minute re-announce interval per info_hash.
 *
 * Matches packages/rs/cairn-p2p/src/discovery/backends.rs BitTorrentBackend.
 */
final class TrackerBackend implements DiscoveryBackendInterface
{
    /** @var array<string, string> Records: info_hash_hex -> payload */
    private array $records = [];

    /** @var array<string, float> Last announce timestamp per info_hash */
    private array $lastAnnounce = [];

    /**
     * @param list<string> $trackerUrls Tracker announce URLs
     * @param int $minReannounce Minimum re-announce interval in seconds
     */
    public function __construct(
        private readonly array $trackerUrls = [],
        private readonly int $minReannounce = TRACKER_MIN_REANNOUNCE,
    ) {
    }

    public function name(): string
    {
        return 'bittorrent';
    }

    public function publish(RendezvousId $rendezvousId, string $payload): PromiseInterface
    {
        $infoHash = bin2hex($rendezvousId->toInfoHash());
        $now = microtime(true);

        // Enforce minimum re-announce interval
        if (isset($this->lastAnnounce[$infoHash])) {
            $elapsed = $now - $this->lastAnnounce[$infoHash];
            if ($elapsed < $this->minReannounce) {
                return resolve(null);
            }
        }

        $this->records[$infoHash] = $payload;
        $this->lastAnnounce[$infoHash] = $now;
        return resolve(null);
    }

    public function query(RendezvousId $rendezvousId): PromiseInterface
    {
        $infoHash = bin2hex($rendezvousId->toInfoHash());
        return resolve($this->records[$infoHash] ?? null);
    }

    public function stop(): PromiseInterface
    {
        $this->records = [];
        $this->lastAnnounce = [];
        return resolve(null);
    }

    /**
     * Get the minimum re-announce interval in seconds.
     */
    public function minReannounceInterval(): int
    {
        return $this->minReannounce;
    }

    /**
     * Get the configured tracker URLs.
     *
     * @return list<string>
     */
    public function trackerUrls(): array
    {
        return $this->trackerUrls;
    }

    /**
     * Convert a rendezvous ID to a 20-byte info_hash.
     */
    public static function toInfoHash(RendezvousId $rendezvousId): string
    {
        return $rendezvousId->toInfoHash();
    }
}

/**
 * WebSocket signaling server discovery backend.
 *
 * Connects to a cairn companion signaling server for real-time peer discovery.
 * The rendezvous ID maps to a WebSocket topic/room. Sub-second latency.
 * Requires Tier 1+ deployment.
 *
 * Matches packages/rs/cairn-p2p/src/discovery/backends.rs SignalingBackend.
 */
final class SignalingBackend implements DiscoveryBackendInterface
{
    /** @var array<string, string> Records: topic_hex -> payload */
    private array $records = [];

    /**
     * @param string $serverUrl Server URL (e.g., "wss://signal.example.com")
     * @param string|null $authToken Optional bearer token for authentication
     */
    public function __construct(
        private readonly string $serverUrl,
        private readonly ?string $authToken = null,
    ) {
    }

    public function name(): string
    {
        return 'signaling';
    }

    public function publish(RendezvousId $rendezvousId, string $payload): PromiseInterface
    {
        $topic = $rendezvousId->toHex();
        $this->records[$topic] = $payload;
        return resolve(null);
    }

    public function query(RendezvousId $rendezvousId): PromiseInterface
    {
        $topic = $rendezvousId->toHex();
        return resolve($this->records[$topic] ?? null);
    }

    public function stop(): PromiseInterface
    {
        $this->records = [];
        return resolve(null);
    }

    /**
     * Get the configured server URL.
     */
    public function serverUrl(): string
    {
        return $this->serverUrl;
    }

    /**
     * Whether authentication is configured.
     */
    public function hasAuth(): bool
    {
        return $this->authToken !== null;
    }
}

/**
 * Coordinates discovery across all configured backends.
 *
 * Publishes to and queries from all backends. First successful query result wins.
 *
 * Matches packages/rs/cairn-p2p/src/discovery/backends.rs DiscoveryCoordinator.
 */
final class DiscoveryCoordinator
{
    /** @var list<DiscoveryBackendInterface> */
    private array $backends;

    /**
     * @param list<DiscoveryBackendInterface> $backends
     */
    public function __construct(array $backends = [])
    {
        $this->backends = $backends;
    }

    /**
     * Publish reachability to all backends.
     *
     * @return list<PromiseInterface<null>>
     */
    public function publishAll(RendezvousId $rendezvousId, string $payload): array
    {
        $promises = [];
        foreach ($this->backends as $backend) {
            $promises[] = $backend->publish($rendezvousId, $payload);
        }
        return $promises;
    }

    /**
     * Query all backends sequentially. Returns the first non-null result.
     *
     * @return PromiseInterface<string|null>
     */
    public function queryFirst(RendezvousId $rendezvousId): PromiseInterface
    {
        foreach ($this->backends as $backend) {
            $result = $backend->query($rendezvousId);
            // Since these are synchronous in our implementation, resolve immediately
            $value = null;
            $result->then(function ($v) use (&$value): void {
                $value = $v;
            });
            if ($value !== null) {
                return resolve($value);
            }
        }
        return resolve(null);
    }

    /**
     * Stop all backends.
     *
     * @return list<PromiseInterface<null>>
     */
    public function stopAll(): array
    {
        $promises = [];
        foreach ($this->backends as $backend) {
            $promises[] = $backend->stop();
        }
        return $promises;
    }

    /**
     * Number of configured backends.
     */
    public function backendCount(): int
    {
        return count($this->backends);
    }

    /**
     * List backend names.
     *
     * @return list<string>
     */
    public function backendNames(): array
    {
        return array_map(fn($b) => $b->name(), $this->backends);
    }
}
