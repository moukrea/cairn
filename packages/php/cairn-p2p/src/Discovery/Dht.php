<?php

declare(strict_types=1);

namespace Cairn\Discovery;

use Cairn\Error\CairnException;
use React\Promise\PromiseInterface;

use function React\Promise\resolve;
use function React\Promise\reject;

/**
 * Kademlia k-bucket size.
 */
const KADEMLIA_K = 20;

/**
 * Kademlia alpha (concurrency parameter for lookups).
 */
const KADEMLIA_ALPHA = 3;

/**
 * DHT record TTL in seconds (24 hours).
 */
const DHT_RECORD_TTL = 86400;

/**
 * UDP port for DHT communication.
 */
const DHT_DEFAULT_PORT = 6881;

/**
 * Maximum UDP packet size for DHT messages.
 */
const DHT_MAX_PACKET_SIZE = 1400;

/**
 * Kademlia DHT-based discovery backend.
 *
 * Implements a lightweight Kademlia DHT client for rendezvous-based peer
 * discovery. Uses UDP for communication with bootstrap nodes and other
 * DHT peers.
 *
 * Protocol: Simplified Kademlia over UDP using bencode-like framing:
 *   STORE: "CAIRN-DHT\x00STORE\x00<key_hex>\x00<base64_payload>"
 *   FIND:  "CAIRN-DHT\x00FIND\x00<key_hex>"
 *   FOUND: "CAIRN-DHT\x00FOUND\x00<key_hex>\x00<base64_payload>"
 *   PEERS: "CAIRN-DHT\x00PEERS\x00<key_hex>\x00<peer1>,<peer2>,..."
 *
 * PHP does not have a libp2p library, so this is a custom implementation
 * compatible with the cairn DHT protocol.
 *
 * Matches packages/rs/cairn-p2p/src/discovery/backends.rs KademliaBackend.
 */
final class DhtBackend implements DiscoveryBackendInterface
{
    /** @var array<string, string> Local records: key_hex -> payload */
    private array $records = [];

    /** @var array<string, int> Record timestamps: key_hex -> unix_timestamp */
    private array $timestamps = [];

    /** @var \Socket|null UDP socket for DHT communication. */
    private ?\Socket $socket = null;

    /** @var array<string, array{host: string, port: int}> Known peers in the routing table. */
    private array $routingTable = [];

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
        $this->timestamps[$key] = time();

        // Attempt to store in the DHT network
        try {
            $this->ensureSocket();
            if ($this->socket !== null) {
                $message = sprintf(
                    "CAIRN-DHT\x00STORE\x00%s\x00%s",
                    $key,
                    base64_encode($payload)
                );

                // Send STORE to bootstrap nodes and known peers
                $targets = $this->getClosestPeers($key);
                foreach ($targets as $peer) {
                    @socket_sendto(
                        $this->socket,
                        $message,
                        strlen($message),
                        0,
                        $peer['host'],
                        $peer['port']
                    );
                }
            }
        } catch (\Throwable) {
            // DHT store failed — record is still stored locally
        }

        return resolve(null);
    }

    public function query(RendezvousId $rendezvousId): PromiseInterface
    {
        $key = $rendezvousId->toHex();

        // Check local records first
        if (isset($this->records[$key])) {
            // Check TTL
            $age = time() - ($this->timestamps[$key] ?? 0);
            if ($age < DHT_RECORD_TTL) {
                return resolve($this->records[$key]);
            }
            // Expired — remove
            unset($this->records[$key], $this->timestamps[$key]);
        }

        // Attempt DHT lookup
        try {
            $this->ensureSocket();
            if ($this->socket !== null) {
                $queryMsg = sprintf("CAIRN-DHT\x00FIND\x00%s", $key);

                // Query bootstrap nodes and known peers
                $targets = $this->getClosestPeers($key);
                foreach ($targets as $peer) {
                    @socket_sendto(
                        $this->socket,
                        $queryMsg,
                        strlen($queryMsg),
                        0,
                        $peer['host'],
                        $peer['port']
                    );
                }

                // Non-blocking read for responses
                $result = $this->receiveResponse($key);
                if ($result !== null) {
                    $this->records[$key] = $result;
                    $this->timestamps[$key] = time();
                    return resolve($result);
                }
            }
        } catch (\Throwable) {
            // DHT lookup failed
        }

        return resolve(null);
    }

    public function stop(): PromiseInterface
    {
        $this->records = [];
        $this->timestamps = [];
        $this->routingTable = [];

        if ($this->socket !== null) {
            @socket_close($this->socket);
            $this->socket = null;
        }

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

    /**
     * Get the number of peers in the routing table.
     */
    public function routingTableSize(): int
    {
        return count($this->routingTable);
    }

    /**
     * Ensure the UDP socket is created and bootstrap nodes are resolved.
     */
    private function ensureSocket(): void
    {
        if ($this->socket !== null) {
            return;
        }

        if (!function_exists('socket_create')) {
            return; // Sockets extension not available
        }

        $sock = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($sock === false) {
            return;
        }

        // Bind to an ephemeral port
        if (!@socket_bind($sock, '0.0.0.0', 0)) {
            @socket_close($sock);
            return;
        }

        @socket_set_nonblock($sock);
        $this->socket = $sock;

        // Populate routing table from bootstrap nodes
        foreach ($this->bootstrapNodes as $node) {
            $parsed = $this->parseAddress($node);
            if ($parsed !== null) {
                $nodeKey = $parsed['host'] . ':' . $parsed['port'];
                $this->routingTable[$nodeKey] = $parsed;
            }
        }
    }

    /**
     * Parse a "host:port" address string.
     *
     * @return array{host: string, port: int}|null
     */
    private function parseAddress(string $address): ?array
    {
        $parts = explode(':', $address);
        if (count($parts) !== 2) {
            return null;
        }

        $host = $parts[0];
        $port = (int) $parts[1];
        if ($port <= 0 || $port > 65535) {
            return null;
        }

        return ['host' => $host, 'port' => $port];
    }

    /**
     * Get the closest peers to a key (XOR distance) from the routing table.
     *
     * Falls back to all bootstrap nodes if routing table is empty.
     *
     * @return list<array{host: string, port: int}>
     */
    private function getClosestPeers(string $keyHex): array
    {
        if (empty($this->routingTable)) {
            // Re-resolve bootstrap nodes
            $peers = [];
            foreach ($this->bootstrapNodes as $node) {
                $parsed = $this->parseAddress($node);
                if ($parsed !== null) {
                    $peers[] = $parsed;
                }
            }
            return array_slice($peers, 0, KADEMLIA_ALPHA);
        }

        // Return up to KADEMLIA_ALPHA closest peers
        // (simplified: just return the first ALPHA peers from the table)
        return array_slice(array_values($this->routingTable), 0, KADEMLIA_ALPHA);
    }

    /**
     * Non-blocking read of DHT responses, looking for a FOUND message
     * matching the given key.
     */
    private function receiveResponse(string $keyHex): ?string
    {
        if ($this->socket === null) {
            return null;
        }

        // Try to read up to 10 packets
        for ($i = 0; $i < 10; $i++) {
            $buf = '';
            $from = '';
            $port = 0;
            $bytes = @socket_recvfrom(
                $this->socket,
                $buf,
                DHT_MAX_PACKET_SIZE,
                0,
                $from,
                $port
            );

            if ($bytes === false || $bytes === 0) {
                break;
            }

            // Update routing table with the responding peer
            $peerKey = $from . ':' . $port;
            $this->routingTable[$peerKey] = ['host' => $from, 'port' => $port];

            // Trim routing table to KADEMLIA_K entries
            if (count($this->routingTable) > KADEMLIA_K) {
                $this->routingTable = array_slice($this->routingTable, -KADEMLIA_K, null, true);
            }

            // Parse response
            $result = $this->parseResponse($buf, $keyHex);
            if ($result !== null) {
                return $result;
            }
        }

        return null;
    }

    /**
     * Parse a DHT response message.
     *
     * @return string|null The payload if this is a FOUND response for our key.
     */
    private function parseResponse(string $message, string $expectedKey): ?string
    {
        $parts = explode("\x00", $message, 4);

        if (count($parts) < 3 || $parts[0] !== 'CAIRN-DHT') {
            return null;
        }

        $type = $parts[1];

        switch ($type) {
            case 'FOUND':
                if (count($parts) === 4 && $parts[2] === $expectedKey) {
                    $payload = base64_decode($parts[3], true);
                    if ($payload !== false) {
                        return $payload;
                    }
                }
                break;

            case 'PEERS':
                // Received peer list — update routing table
                if (count($parts) >= 4) {
                    $peerList = explode(',', $parts[3]);
                    foreach ($peerList as $peerAddr) {
                        $parsed = $this->parseAddress(trim($peerAddr));
                        if ($parsed !== null) {
                            $key = $parsed['host'] . ':' . $parsed['port'];
                            $this->routingTable[$key] = $parsed;
                        }
                    }
                }
                break;

            case 'STORE':
                // Another peer storing a record — accept it
                if (count($parts) === 4) {
                    $storeKey = $parts[2];
                    $payload = base64_decode($parts[3], true);
                    if ($payload !== false) {
                        $this->records[$storeKey] = $payload;
                        $this->timestamps[$storeKey] = time();
                    }
                }
                break;

            case 'FIND':
                // Another peer querying — respond if we have the record
                if (count($parts) >= 3) {
                    $findKey = $parts[2];
                    if (isset($this->records[$findKey])) {
                        // Note: We can't respond here without sender info
                        // in a stateless manner. In a real implementation,
                        // the FIND message would include a return address.
                    }
                }
                break;
        }

        return null;
    }
}
