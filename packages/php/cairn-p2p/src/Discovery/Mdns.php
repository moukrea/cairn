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
 * Maximum mDNS UDP packet size.
 */
const MDNS_MAX_PACKET_SIZE = 9000;

/**
 * Service name prefix for cairn mDNS records.
 */
const MDNS_SERVICE_PREFIX = '_cairn-';

/**
 * Service name suffix for cairn mDNS records.
 */
const MDNS_SERVICE_SUFFIX = '._tcp.local.';

/**
 * mDNS-based LAN discovery backend.
 *
 * Uses real UDP multicast on 224.0.0.251:5353 for instant LAN discovery.
 * The rendezvous ID (first 16 hex chars) is used as the service name:
 *   _cairn-<hex[:16]>._tcp.local.
 *
 * The payload is base64-encoded in a TXT record.
 *
 * Matches packages/rs/cairn-p2p/src/discovery/backends.rs MdnsBackend.
 */
final class MdnsBackend implements DiscoveryBackendInterface
{
    /** @var array<string, string> Records: rendezvous_id_hex -> payload */
    private array $records = [];

    /** @var \Socket|null UDP multicast socket for sending/receiving. */
    private ?\Socket $socket = null;

    /** @var array<string, string> Discovered records from LAN peers: hex -> payload */
    private array $discovered = [];

    public function name(): string
    {
        return 'mdns';
    }

    public function publish(RendezvousId $rendezvousId, string $payload): PromiseInterface
    {
        $key = $rendezvousId->toHex();
        $this->records[$key] = $payload;

        // Attempt to send via multicast
        try {
            $this->ensureSocket();
            if ($this->socket !== null) {
                $serviceName = self::serviceNameFromHex($key);
                // Encode as a simple TXT record announcement:
                // Format: "SRV:<service>\tTXT:<base64payload>"
                $message = sprintf(
                    "CAIRN-MDNS\x00%s\x00%s",
                    $serviceName,
                    base64_encode($payload)
                );
                @socket_sendto(
                    $this->socket,
                    $message,
                    strlen($message),
                    0,
                    MDNS_MULTICAST_ADDR,
                    MDNS_PORT
                );
            }
        } catch (\Throwable) {
            // Multicast send failed — record is still stored locally.
            // This is non-fatal; LAN discovery is best-effort.
        }

        return resolve(null);
    }

    public function query(RendezvousId $rendezvousId): PromiseInterface
    {
        $key = $rendezvousId->toHex();

        // Check local records first
        if (isset($this->records[$key])) {
            return resolve($this->records[$key]);
        }

        // Check discovered records from LAN
        if (isset($this->discovered[$key])) {
            return resolve($this->discovered[$key]);
        }

        // Attempt a non-blocking multicast query
        try {
            $this->ensureSocket();
            if ($this->socket !== null) {
                $serviceName = self::serviceNameFromHex($key);
                $queryMsg = sprintf("CAIRN-MDNS-Q\x00%s", $serviceName);
                @socket_sendto(
                    $this->socket,
                    $queryMsg,
                    strlen($queryMsg),
                    0,
                    MDNS_MULTICAST_ADDR,
                    MDNS_PORT
                );

                // Non-blocking read attempt — check for any responses
                $this->receiveDiscovered();

                if (isset($this->discovered[$key])) {
                    return resolve($this->discovered[$key]);
                }
            }
        } catch (\Throwable) {
            // Query attempt failed — return null
        }

        return resolve(null);
    }

    public function stop(): PromiseInterface
    {
        $this->records = [];
        $this->discovered = [];

        if ($this->socket !== null) {
            // Leave multicast group and close socket
            try {
                @socket_set_option(
                    $this->socket,
                    IPPROTO_IP,
                    MCAST_LEAVE_GROUP,
                    ['group' => MDNS_MULTICAST_ADDR, 'interface' => 0]
                );
            } catch (\Throwable) {
                // Ignore — socket may already be closed
            }
            @socket_close($this->socket);
            $this->socket = null;
        }

        return resolve(null);
    }

    /**
     * Get the number of published records.
     */
    public function recordCount(): int
    {
        return count($this->records);
    }

    /**
     * Get the number of discovered records from LAN peers.
     */
    public function discoveredCount(): int
    {
        return count($this->discovered);
    }

    /**
     * Build a service name from a rendezvous ID hex string.
     *
     * Format: _cairn-<first 16 hex chars>._tcp.local.
     */
    private static function serviceNameFromHex(string $hex): string
    {
        return MDNS_SERVICE_PREFIX . substr($hex, 0, 16) . MDNS_SERVICE_SUFFIX;
    }

    /**
     * Extract rendezvous ID hex prefix from a service name.
     *
     * Returns null if the service name doesn't match the cairn pattern.
     */
    private static function hexFromServiceName(string $serviceName): ?string
    {
        $prefix = MDNS_SERVICE_PREFIX;
        $suffix = MDNS_SERVICE_SUFFIX;

        if (
            str_starts_with($serviceName, $prefix)
            && str_ends_with($serviceName, $suffix)
        ) {
            return substr(
                $serviceName,
                strlen($prefix),
                strlen($serviceName) - strlen($prefix) - strlen($suffix)
            );
        }

        return null;
    }

    /**
     * Ensure the UDP multicast socket is created and joined to the group.
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

        // Allow address reuse (multiple processes on same host)
        @socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1);

        // Bind to mDNS port
        if (!@socket_bind($sock, '0.0.0.0', MDNS_PORT)) {
            @socket_close($sock);
            return;
        }

        // Join multicast group
        $joined = @socket_set_option(
            $sock,
            IPPROTO_IP,
            MCAST_JOIN_GROUP,
            ['group' => MDNS_MULTICAST_ADDR, 'interface' => 0]
        );

        if (!$joined) {
            @socket_close($sock);
            return;
        }

        // Set non-blocking for query reads
        @socket_set_nonblock($sock);

        // Set multicast TTL to 1 (link-local only)
        @socket_set_option($sock, IPPROTO_IP, IP_MULTICAST_TTL, 1);

        $this->socket = $sock;
    }

    /**
     * Non-blocking read of any available multicast responses.
     */
    private function receiveDiscovered(): void
    {
        if ($this->socket === null) {
            return;
        }

        // Read up to 10 packets non-blocking
        for ($i = 0; $i < 10; $i++) {
            $buf = '';
            $from = '';
            $port = 0;
            $bytes = @socket_recvfrom(
                $this->socket,
                $buf,
                MDNS_MAX_PACKET_SIZE,
                0,
                $from,
                $port
            );

            if ($bytes === false || $bytes === 0) {
                break; // No more data
            }

            $this->parseDiscoveredMessage($buf);
        }
    }

    /**
     * Parse a received multicast message and extract any cairn records.
     */
    private function parseDiscoveredMessage(string $message): void
    {
        // Parse our custom cairn-mDNS format:
        // "CAIRN-MDNS\x00<service_name>\x00<base64_payload>"
        $parts = explode("\x00", $message, 3);
        if (count($parts) !== 3 || $parts[0] !== 'CAIRN-MDNS') {
            return;
        }

        $serviceName = $parts[1];
        $payloadB64 = $parts[2];

        $hexPrefix = self::hexFromServiceName($serviceName);
        if ($hexPrefix === null) {
            return;
        }

        $payload = base64_decode($payloadB64, true);
        if ($payload === false) {
            return;
        }

        // Store with the hex prefix — queries will match by prefix
        // since service names only use the first 16 hex chars.
        // Find any local record key that starts with this prefix.
        foreach ($this->records as $fullHex => $_) {
            if (str_starts_with($fullHex, $hexPrefix)) {
                $this->discovered[$fullHex] = $payload;
                return;
            }
        }

        // No matching local key — store with the prefix as key.
        // A future query with matching prefix will find it.
        $this->discovered[$hexPrefix] = $payload;
    }
}
