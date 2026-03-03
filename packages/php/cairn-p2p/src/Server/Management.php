<?php

declare(strict_types=1);

namespace Cairn\Server;

use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;

// ---------------------------------------------------------------------------
// Server-mode configuration posture (spec 10.2)
// ---------------------------------------------------------------------------

/**
 * Server-mode configuration posture.
 *
 * Server mode is not a separate class or protocol -- it is a standard Node
 * with adjusted defaults. The Node::createServer($config) convenience
 * constructor applies these defaults.
 *
 * Matches packages/rs/cairn-p2p/src/server/mod.rs ServerConfig.
 */
final class ServerConfig
{
    public function __construct(
        public readonly bool $meshEnabled = true,
        public readonly bool $relayWilling = true,
        public readonly int $relayCapacity = 100,
        public readonly bool $storeForwardEnabled = true,
        public readonly int $storeForwardMaxPerPeer = 1000,
        /** Maximum message age in seconds. Default: 7 days. */
        public readonly int $storeForwardMaxAge = 604800,
        /** Maximum total store-and-forward storage in bytes. Default: 1 GB. */
        public readonly int $storeForwardMaxTotalSize = 1_073_741_824,
        /** Session expiry in seconds. Default: 7 days. */
        public readonly int $sessionExpiry = 604800,
        /** Heartbeat interval in seconds. Default: 60. */
        public readonly int $heartbeatInterval = 60,
        /** Reconnect max duration in seconds. null = indefinite. */
        public readonly ?float $reconnectMaxDuration = null,
        public readonly bool $headless = true,
    ) {
    }

    /**
     * Build a RetentionPolicy from this server config.
     */
    public function retentionPolicy(): RetentionPolicy
    {
        return new RetentionPolicy(
            maxAge: $this->storeForwardMaxAge,
            maxMessages: $this->storeForwardMaxPerPeer,
        );
    }
}

// ---------------------------------------------------------------------------
// Headless pairing (spec 10.5)
// ---------------------------------------------------------------------------

/**
 * Default validity window for headless pairing payloads (5 minutes).
 */
const DEFAULT_VALIDITY_WINDOW = 300;

/**
 * Environment variable name for pre-shared key.
 */
const PSK_ENV_VAR = 'CAIRN_PSK';

/**
 * A generated headless pairing method with its payload and expiration.
 *
 * Matches packages/rs/cairn-p2p/src/server/headless.rs HeadlessPairingMethod.
 */
final class HeadlessPairingMethod
{
    public function __construct(
        public readonly HeadlessPairingMethodType $type,
        /** PSK bytes, pin string, URI string, or ASCII art depending on type. */
        public readonly string $value,
        /** When this method expires (microtime). null = never (PSK). */
        public readonly ?float $expiresAt = null,
    ) {
    }

    /**
     * Check whether this method's payload has expired.
     */
    public function isExpired(): bool
    {
        if ($this->expiresAt === null) {
            return false; // PSK does not expire
        }
        return microtime(true) >= $this->expiresAt;
    }
}

/**
 * Headless pairing controller for server-mode peers (spec 10.5).
 *
 * Generates pairing payloads using mechanisms that work without a display,
 * keyboard, or camera. SAS verification is excluded.
 *
 * Matches packages/rs/cairn-p2p/src/server/headless.rs HeadlessPairing.
 */
final class HeadlessPairing
{
    public function __construct(
        /** Validity window in seconds. Default: 5 minutes. */
        public readonly int $validityWindow = DEFAULT_VALIDITY_WINDOW,
    ) {
    }

    /**
     * Generate a pre-shared key pairing method.
     *
     * Loads PSK from provided bytes or CAIRN_PSK environment variable.
     * Validates minimum entropy (128 bits = 16 bytes).
     *
     * @throws CairnException
     */
    public function generatePsk(?string $psk = null): HeadlessPairingMethod
    {
        if ($psk === null) {
            $envVal = getenv(PSK_ENV_VAR);
            if ($envVal === false) {
                throw new CairnException(
                    'PSK not configured (set ' . PSK_ENV_VAR . ' env var or provide via config)',
                );
            }
            $psk = $envVal;
        }

        // Validate minimum entropy (128 bits)
        if (strlen($psk) < 16) {
            throw new CairnException(
                sprintf('PSK too short: %d bytes, minimum 16 (128 bits)', strlen($psk)),
            );
        }

        return new HeadlessPairingMethod(
            type: HeadlessPairingMethodType::PreSharedKey,
            value: $psk,
        );
    }

    /**
     * Generate a pin code pairing method.
     *
     * Returns a formatted XXXX-XXXX pin code.
     */
    public function generatePin(): HeadlessPairingMethod
    {
        $bytes = random_bytes(4);
        $num = unpack('N', $bytes)[1] & 0x7FFFFFFF;
        $pin = sprintf('%04d-%04d', intdiv($num, 10000) % 10000, $num % 10000);

        return new HeadlessPairingMethod(
            type: HeadlessPairingMethodType::PinCode,
            value: $pin,
            expiresAt: microtime(true) + $this->validityWindow,
        );
    }

    /**
     * Generate a pairing link method.
     *
     * Returns a cairn://pair?... URI.
     */
    public function generateLink(string $peerId, string $nonce, string $pakeCredential): HeadlessPairingMethod
    {
        $params = http_build_query([
            'pid' => $peerId,
            'nonce' => bin2hex($nonce),
            'pake' => bin2hex($pakeCredential),
        ]);

        return new HeadlessPairingMethod(
            type: HeadlessPairingMethodType::PairingLink,
            value: 'cairn://pair?' . $params,
            expiresAt: microtime(true) + $this->validityWindow,
        );
    }

    /**
     * Check whether SAS verification is available in headless mode.
     *
     * Always returns false -- SAS requires a display for visual comparison.
     */
    public function sasAvailable(): bool
    {
        return false;
    }

    /**
     * List the mechanisms supported in headless mode.
     *
     * @return list<string>
     */
    public function supportedMechanisms(): array
    {
        return ['psk', 'pin', 'link', 'qr'];
    }
}

// ---------------------------------------------------------------------------
// PersonalRelayConfig (spec 10.4)
// ---------------------------------------------------------------------------

/**
 * Personal relay configuration for server-mode peers.
 *
 * A server-mode peer with a public IP relays traffic between paired peers
 * who cannot connect directly. Only serves paired peers.
 *
 * Matches packages/rs/cairn-p2p/src/server/headless.rs PersonalRelayConfig.
 */
final class PersonalRelayConfig
{
    /**
     * @param bool $relayWilling Whether the server is willing to relay traffic
     * @param int $relayCapacity Maximum concurrent relay sessions
     * @param list<PeerId> $allowedPeers Allowed peer IDs (empty = all paired peers)
     */
    public function __construct(
        public readonly bool $relayWilling = true,
        public readonly int $relayCapacity = 100,
        public readonly array $allowedPeers = [],
    ) {
    }

    /**
     * Check whether a peer is allowed to use this relay.
     *
     * If allowedPeers is empty, all peers are allowed (caller verifies pairing).
     */
    public function isPeerAllowed(PeerId $peerId): bool
    {
        if ($this->allowedPeers === []) {
            return true;
        }

        foreach ($this->allowedPeers as $allowed) {
            if ($allowed->equals($peerId)) {
                return true;
            }
        }
        return false;
    }
}

// ---------------------------------------------------------------------------
// Multi-device sync (spec 10.6)
// ---------------------------------------------------------------------------

/**
 * Per-peer synchronization state tracked by the server node.
 *
 * Used for multi-device sync: the server tracks what each peer has seen
 * so that when a device reconnects, it receives everything it missed.
 *
 * Matches packages/rs/cairn-p2p/src/server/headless.rs PeerSyncState.
 */
final class PeerSyncState
{
    public int $lastSeenSequence = 0;
    public int $pendingDeliveries = 0;
    public ?float $lastConnected = null;

    public function __construct(
        public readonly PeerId $peerId,
    ) {
    }

    /**
     * Record that the peer has connected.
     */
    public function markConnected(): void
    {
        $this->lastConnected = microtime(true);
    }

    /**
     * Update the last-seen sequence number after delivering messages.
     */
    public function advanceSequence(int $seq): void
    {
        if ($seq > $this->lastSeenSequence) {
            $delivered = $seq - $this->lastSeenSequence;
            $this->lastSeenSequence = $seq;
            $this->pendingDeliveries = max(0, $this->pendingDeliveries - $delivered);
        }
    }

    /**
     * Increment the pending delivery count by one.
     */
    public function enqueueDelivery(): void
    {
        if ($this->pendingDeliveries < PHP_INT_MAX) {
            $this->pendingDeliveries++;
        }
    }

    /**
     * Increment the pending delivery count by a given amount.
     */
    public function addPending(int $count): void
    {
        $this->pendingDeliveries = min(PHP_INT_MAX, $this->pendingDeliveries + $count);
    }

    /**
     * Decrement the pending delivery count after successful delivery.
     */
    public function acknowledgeDelivery(int $count): void
    {
        $this->pendingDeliveries = max(0, $this->pendingDeliveries - $count);
    }
}

// ---------------------------------------------------------------------------
// Resource accounting (spec 10.7)
// ---------------------------------------------------------------------------

/**
 * Per-peer resource metrics tracked by the server.
 *
 * Matches packages/rs/cairn-p2p/src/server/headless.rs PeerMetrics.
 */
final class PeerMetrics
{
    public int $bytesRelayed = 0;
    public int $bytesStored = 0;

    public function __construct(
        public readonly PeerId $peerId,
    ) {
    }

    /**
     * Record bytes relayed for this peer.
     */
    public function recordRelay(int $bytes): void
    {
        $this->bytesRelayed = min(PHP_INT_MAX, $this->bytesRelayed + $bytes);
    }

    /**
     * Record bytes stored for this peer.
     */
    public function recordStore(int $bytes): void
    {
        $this->bytesStored = min(PHP_INT_MAX, $this->bytesStored + $bytes);
    }

    /**
     * Decrease stored bytes after delivery/purge.
     */
    public function releaseStored(int $bytes): void
    {
        $this->bytesStored = max(0, $this->bytesStored - $bytes);
    }
}

/**
 * Per-peer resource quotas. Configurable, disabled by default.
 *
 * When a quota is null, that resource is unlimited.
 *
 * Matches packages/rs/cairn-p2p/src/server/headless.rs PeerQuota.
 */
final class PeerQuota
{
    public function __construct(
        /** Maximum stored messages in the store-and-forward queue. */
        public readonly ?int $maxStoredMessages = null,
        /** Maximum relay bandwidth in bytes per second. */
        public readonly ?int $maxRelayBandwidthBps = null,
    ) {
    }

    /**
     * Check whether the stored message count is within quota.
     */
    public function checkStoreQuota(int $currentMessages): bool
    {
        if ($this->maxStoredMessages === null) {
            return true;
        }
        return $currentMessages < $this->maxStoredMessages;
    }

    /**
     * Check whether the relay bandwidth is within quota.
     */
    public function checkRelayQuota(int $currentBps): bool
    {
        if ($this->maxRelayBandwidthBps === null) {
            return true;
        }
        return $currentBps <= $this->maxRelayBandwidthBps;
    }
}

// ---------------------------------------------------------------------------
// Management API config (spec 10.5)
// ---------------------------------------------------------------------------

/**
 * Management API configuration.
 *
 * Matches packages/rs/cairn-p2p/src/server/management.rs ManagementConfig.
 */
final class ManagementConfig
{
    public function __construct(
        public readonly bool $enabled = false,
        public readonly string $bindAddress = '127.0.0.1',
        public readonly int $port = 9090,
        public readonly string $authToken = '',
    ) {
    }

    /**
     * Whether the bind address is loopback.
     */
    public function isLoopback(): bool
    {
        return in_array($this->bindAddress, ['127.0.0.1', '::1', 'localhost'], true);
    }
}

// ---------------------------------------------------------------------------
// Management API data types
// ---------------------------------------------------------------------------

/**
 * Information about a paired peer for the management API.
 */
final class MgmtPeerInfo
{
    public function __construct(
        public readonly string $peerId,
        public readonly string $name,
        public readonly bool $connected,
        public readonly ?string $lastSeen = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'peer_id' => $this->peerId,
            'name' => $this->name,
            'connected' => $this->connected,
            'last_seen' => $this->lastSeen,
        ];
    }
}

/**
 * Per-peer store-and-forward queue info.
 */
final class QueueInfo
{
    public function __construct(
        public readonly string $peerId,
        public readonly int $pendingMessages,
        public readonly ?float $oldestMessageAgeSecs = null,
        public readonly int $totalBytes = 0,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'peer_id' => $this->peerId,
            'pending_messages' => $this->pendingMessages,
            'oldest_message_age_secs' => $this->oldestMessageAgeSecs,
            'total_bytes' => $this->totalBytes,
        ];
    }
}

/**
 * Per-peer relay statistics.
 */
final class PeerRelayStats
{
    public function __construct(
        public readonly string $peerId,
        public readonly int $bytesRelayed = 0,
        public readonly int $activeStreams = 0,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'peer_id' => $this->peerId,
            'bytes_relayed' => $this->bytesRelayed,
            'active_streams' => $this->activeStreams,
        ];
    }
}

/**
 * Relay statistics overview.
 */
final class RelayStats
{
    /**
     * @param list<PeerRelayStats> $perPeer
     */
    public function __construct(
        public readonly int $activeConnections = 0,
        public readonly array $perPeer = [],
    ) {
    }
}

// ---------------------------------------------------------------------------
// Management state
// ---------------------------------------------------------------------------

/**
 * Shared state accessible by all management API handlers.
 */
final class ManagementState
{
    /** @var list<MgmtPeerInfo> */
    public array $peers = [];

    /** @var list<QueueInfo> */
    public array $queues = [];

    public RelayStats $relayStats;

    public readonly float $startedAt;

    public function __construct(
        public readonly string $authToken,
    ) {
        $this->relayStats = new RelayStats();
        $this->startedAt = microtime(true);
    }
}

// ---------------------------------------------------------------------------
// Management HTTP server (spec 10.5, 10.7)
// ---------------------------------------------------------------------------

/**
 * Synchronous HTTP management API server using PHP stream sockets.
 *
 * Serves 5 endpoints: /peers, /queues, /relay/stats, /health, /pairing/qr.
 * Uses bearer token authentication with constant-time comparison.
 *
 * Matches packages/py/cairn-p2p/src/cairn/server/management.py ManagementServer.
 */
final class ManagementServer
{
    private ManagementConfig $config;
    private ManagementState $state;
    /** @var resource|null */
    private $socket = null;

    public function __construct(ManagementConfig $config, ManagementState $state)
    {
        if ($config->authToken === '') {
            throw new \InvalidArgumentException('management API auth token is empty');
        }

        if (!$config->isLoopback()) {
            trigger_error(
                sprintf(
                    'Management API exposed on non-loopback interface %s without TLS. This is insecure.',
                    $config->bindAddress,
                ),
                E_USER_WARNING,
            );
        }

        $this->config = $config;
        $this->state = $state;
    }

    /**
     * Start the management API server (creates listening socket).
     *
     * @throws \RuntimeException
     */
    public function start(): void
    {
        $address = sprintf('tcp://%s:%d', $this->config->bindAddress, $this->config->port);
        $ctx = stream_context_create(['socket' => ['so_reuseaddr' => true]]);
        $this->socket = @stream_socket_server($address, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
        if ($this->socket === false) {
            throw new \RuntimeException("Failed to bind management API: $errstr ($errno)");
        }
        stream_set_blocking($this->socket, false);
    }

    /**
     * Stop the management API server.
     */
    public function stop(): void
    {
        if ($this->socket !== null) {
            fclose($this->socket);
            $this->socket = null;
        }
    }

    /**
     * Return the actual port (useful when port=0).
     */
    public function port(): int
    {
        if ($this->socket !== null) {
            $name = stream_socket_get_name($this->socket, false);
            if ($name !== false) {
                $parts = explode(':', $name);
                return (int) end($parts);
            }
        }
        return $this->config->port;
    }

    /**
     * Handle a single incoming request (blocking accept + handle).
     *
     * Returns false if no connection was available.
     */
    public function handleOne(float $timeout = 0.0): bool
    {
        if ($this->socket === null) {
            return false;
        }

        $conn = @stream_socket_accept($this->socket, $timeout);
        if ($conn === false) {
            return false;
        }

        try {
            $this->handleConnection($conn);
        } finally {
            fclose($conn);
        }

        return true;
    }

    /**
     * Handle a single HTTP connection.
     *
     * @param resource $conn
     */
    private function handleConnection($conn): void
    {
        stream_set_timeout($conn, 10);

        // Read request line
        $line = fgets($conn, 8192);
        if ($line === false) {
            return;
        }

        $parts = explode(' ', trim($line));
        if (count($parts) < 2) {
            $this->sendResponse($conn, 400, ['error' => 'bad request']);
            return;
        }

        $method = $parts[0];
        $path = $parts[1];

        // Read headers
        $headers = [];
        while (($headerLine = fgets($conn, 8192)) !== false) {
            $trimmed = trim($headerLine);
            if ($trimmed === '') {
                break;
            }
            $colonPos = strpos($trimmed, ':');
            if ($colonPos !== false) {
                $key = strtolower(trim(substr($trimmed, 0, $colonPos)));
                $value = trim(substr($trimmed, $colonPos + 1));
                $headers[$key] = $value;
            }
        }

        // Authentication
        $auth = $headers['authorization'] ?? '';
        if (!str_starts_with($auth, 'Bearer ')) {
            $this->sendResponse($conn, 401, ['error' => 'unauthorized']);
            return;
        }

        $provided = substr($auth, 7);
        if (!hash_equals($this->state->authToken, $provided)) {
            $this->sendResponse($conn, 401, ['error' => 'unauthorized']);
            return;
        }

        // Only GET supported
        if ($method !== 'GET') {
            $this->sendResponse($conn, 405, ['error' => 'method not allowed']);
            return;
        }

        // Route
        $body = match ($path) {
            '/peers' => $this->handlePeers(),
            '/queues' => $this->handleQueues(),
            '/relay/stats' => $this->handleRelayStats(),
            '/health' => $this->handleHealth(),
            '/pairing/qr' => null,
            default => null,
        };

        if ($path === '/pairing/qr') {
            $this->sendResponse($conn, 503, [
                'error' => 'pairing QR generation not yet available (pending headless pairing integration)',
            ]);
            return;
        }

        if ($body === null) {
            $this->sendResponse($conn, 404, ['error' => 'not found']);
            return;
        }

        $this->sendResponse($conn, 200, $body);
    }

    /**
     * @return array<string, mixed>
     */
    private function handlePeers(): array
    {
        return [
            'peers' => array_map(
                static fn(MgmtPeerInfo $p) => $p->toArray(),
                $this->state->peers,
            ),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function handleQueues(): array
    {
        return [
            'queues' => array_map(
                static fn(QueueInfo $q) => $q->toArray(),
                $this->state->queues,
            ),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function handleRelayStats(): array
    {
        $stats = $this->state->relayStats;
        return [
            'relay' => [
                'active_connections' => $stats->activeConnections,
                'per_peer' => array_map(
                    static fn(PeerRelayStats $p) => $p->toArray(),
                    $stats->perPeer,
                ),
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function handleHealth(): array
    {
        $totalPeers = count($this->state->peers);
        $connectedPeers = count(array_filter(
            $this->state->peers,
            static fn(MgmtPeerInfo $p) => $p->connected,
        ));
        $uptimeSecs = (int) floor(microtime(true) - $this->state->startedAt);
        $status = $connectedPeers > 0 ? 'healthy' : 'degraded';

        return [
            'status' => $status,
            'uptime_secs' => $uptimeSecs,
            'connected_peers' => $connectedPeers,
            'total_peers' => $totalPeers,
        ];
    }

    /**
     * Send an HTTP response with JSON body.
     *
     * @param resource $conn
     * @param array<string, mixed> $body
     */
    private function sendResponse($conn, int $statusCode, array $body): void
    {
        $phrases = [
            200 => 'OK',
            400 => 'Bad Request',
            401 => 'Unauthorized',
            404 => 'Not Found',
            405 => 'Method Not Allowed',
            503 => 'Service Unavailable',
        ];
        $phrase = $phrases[$statusCode] ?? 'Unknown';
        $bodyJson = json_encode($body, JSON_UNESCAPED_SLASHES);

        $response = sprintf(
            "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
            $statusCode,
            $phrase,
            strlen($bodyJson),
            $bodyJson,
        );

        fwrite($conn, $response);
    }
}
