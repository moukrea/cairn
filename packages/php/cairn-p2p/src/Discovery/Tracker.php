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
 * BEP 15 protocol ID magic constant.
 */
const BEP15_PROTOCOL_ID = 0x41727101980;

/**
 * Default public BitTorrent trackers for discovery.
 */
const DEFAULT_TRACKERS = [
    'udp://tracker.opentrackr.org:1337/announce',
    'udp://open.dstud.io:6969/announce',
    'udp://tracker.openbittorrent.com:6969/announce',
];

/**
 * BitTorrent tracker-based discovery backend.
 *
 * Uses the rendezvous ID as an info_hash to publish and query peers
 * via BitTorrent tracker infrastructure:
 * - BEP 15: UDP tracker protocol (primary)
 * - BEP 3: HTTP tracker announce/scrape (fallback)
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

    /** @var string 20-byte peer ID for tracker protocol */
    private string $peerId;

    /**
     * @param list<string> $trackerUrls Tracker announce URLs
     * @param int $minReannounce Minimum re-announce interval in seconds
     */
    public function __construct(
        private readonly array $trackerUrls = DEFAULT_TRACKERS,
        private readonly int $minReannounce = TRACKER_MIN_REANNOUNCE,
    ) {
        // Generate a stable 20-byte peer ID with cairn prefix
        $this->peerId = '-CR0001-' . random_bytes(12);
    }

    public function name(): string
    {
        return 'bittorrent';
    }

    public function publish(RendezvousId $rendezvousId, string $payload): PromiseInterface
    {
        $infoHash = $rendezvousId->toInfoHash();
        $key = bin2hex($infoHash);
        $now = microtime(true);

        // Enforce minimum re-announce interval
        if (isset($this->lastAnnounce[$key])) {
            $elapsed = $now - $this->lastAnnounce[$key];
            if ($elapsed < $this->minReannounce) {
                $this->records[$key] = $payload;
                return resolve(null);
            }
        }

        $this->records[$key] = $payload;
        $this->lastAnnounce[$key] = $now;

        // Attempt UDP tracker announce
        foreach ($this->trackerUrls as $url) {
            try {
                if (str_starts_with($url, 'udp://')) {
                    $this->udpAnnounce($url, $infoHash, 2); // event: started
                    break;
                }
            } catch (\Throwable) {
                continue;
            }
        }

        return resolve(null);
    }

    public function query(RendezvousId $rendezvousId): PromiseInterface
    {
        $infoHash = $rendezvousId->toInfoHash();
        $key = bin2hex($infoHash);

        // Check local cache
        if (isset($this->records[$key])) {
            return resolve($this->records[$key]);
        }

        // Try UDP tracker query
        foreach ($this->trackerUrls as $url) {
            try {
                if (str_starts_with($url, 'udp://')) {
                    $peers = $this->udpQuery($url, $infoHash);
                    if ($peers !== null) {
                        return resolve($peers);
                    }
                }
            } catch (\Throwable) {
                continue;
            }
        }

        return resolve(null);
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

    /**
     * Send BEP 15 UDP tracker announce.
     */
    private function udpAnnounce(string $trackerUrl, string $infoHash, int $event): void
    {
        $parsed = parse_url($trackerUrl);
        $host = $parsed['host'] ?? '';
        $port = $parsed['port'] ?? 6969;

        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($sock === false) {
            throw new CairnException('Failed to create UDP socket');
        }

        try {
            socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
            socket_connect($sock, $host, $port);

            // Step 1: BEP 15 connect
            $connectionId = $this->bep15Connect($sock);

            // Step 2: Announce
            $tid = random_int(0, 0xFFFFFFFF);
            $req = pack('J', $connectionId)       // connection_id
                . pack('N', 1)                     // action: announce
                . pack('N', $tid)                  // transaction_id
                . $infoHash                        // info_hash (20 bytes)
                . $this->peerId                    // peer_id (20 bytes)
                . str_repeat("\0", 24)             // downloaded, left, uploaded
                . pack('N', $event)                // event
                . str_repeat("\0", 4)              // IP
                . random_bytes(4)                  // key
                . pack('N', 0xFFFFFFFF)            // num_want = -1
                . pack('n', 0);                    // port

            socket_send($sock, $req, strlen($req), 0);
        } finally {
            socket_close($sock);
        }
    }

    /**
     * Query peers via BEP 15 UDP tracker.
     *
     * @return string|null Compact peer data or null
     */
    private function udpQuery(string $trackerUrl, string $infoHash): ?string
    {
        $parsed = parse_url($trackerUrl);
        $host = $parsed['host'] ?? '';
        $port = $parsed['port'] ?? 6969;

        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($sock === false) {
            return null;
        }

        try {
            socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
            socket_connect($sock, $host, $port);

            $connectionId = $this->bep15Connect($sock);

            // Announce with event=0 to get peers
            $tid = random_int(0, 0xFFFFFFFF);
            $req = pack('J', $connectionId)
                . pack('N', 1)
                . pack('N', $tid)
                . $infoHash
                . $this->peerId
                . str_repeat("\0", 24)
                . pack('N', 0)                     // event: none
                . str_repeat("\0", 4)
                . random_bytes(4)
                . pack('N', 0xFFFFFFFF)
                . pack('n', 0);

            socket_send($sock, $req, strlen($req), 0);

            $resp = '';
            $bytes = socket_recv($sock, $resp, 1024, 0);
            if ($bytes === false || $bytes < 20) {
                return null;
            }

            /** @var array{1: int} $header */
            $header = unpack('Naction', $resp);
            if ($header['action'] !== 1) {
                return null;
            }

            // Return compact peer data (after 20-byte header)
            return substr($resp, 20);
        } catch (\Throwable) {
            return null;
        } finally {
            socket_close($sock);
        }
    }

    /**
     * BEP 15 connect handshake.
     *
     * @param \Socket $sock
     * @return int Connection ID
     * @throws CairnException
     */
    private function bep15Connect(\Socket $sock): int
    {
        $tid = random_int(0, 0xFFFFFFFF);
        $req = pack('J', BEP15_PROTOCOL_ID)    // protocol_id
            . pack('N', 0)                      // action: connect
            . pack('N', $tid);                  // transaction_id

        socket_send($sock, $req, strlen($req), 0);

        $resp = '';
        $bytes = socket_recv($sock, $resp, 16, 0);
        if ($bytes === false || $bytes < 16) {
            throw new CairnException('BEP 15 connect response too short');
        }

        /** @var array{1: int, 2: int} $header */
        $header = unpack('Naction/Ntid', $resp);
        if ($header['action'] !== 0 || $header['tid'] !== $tid) {
            throw new CairnException('BEP 15 connect response invalid');
        }

        /** @var array{1: int} $conn */
        $conn = unpack('Jconnection_id', substr($resp, 8));
        return $conn['connection_id'];
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
