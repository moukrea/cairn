<?php

declare(strict_types=1);

namespace Cairn;

use Cairn\Error\CairnException;

/**
 * TURN relay server credentials.
 */
final class TurnServer
{
    public function __construct(
        public readonly string $url,
        public readonly string $username,
        public readonly string $credential,
    ) {
    }
}

/**
 * Reconnection and timeout policy (spec section 2.2).
 *
 * Matches packages/rs/cairn-p2p/src/config.rs ReconnectionPolicy.
 */
final class ReconnectionPolicy
{
    public function __construct(
        /** Connect timeout in seconds. Default: 30. */
        public readonly float $connectTimeout = 30.0,
        /** Transport timeout in seconds. Default: 10. */
        public readonly float $transportTimeout = 10.0,
        /** Max reconnection duration in seconds. Default: 3600 (1 hour). */
        public readonly float $reconnectMaxDuration = 3600.0,
        /** Initial backoff delay in seconds. Default: 1.0. */
        public readonly float $reconnectBackoffInitial = 1.0,
        /** Maximum backoff delay in seconds. Default: 60.0. */
        public readonly float $reconnectBackoffMax = 60.0,
        /** Backoff multiplier. Default: 2.0. Must be > 1.0. */
        public readonly float $reconnectBackoffFactor = 2.0,
        /** Rendezvous poll interval in seconds. Default: 30. */
        public readonly float $rendezvousPollInterval = 30.0,
        /** Session expiry in seconds. Default: 86400 (1 day). */
        public readonly float $sessionExpiry = 86400.0,
        /** Pairing payload expiry in seconds. Default: 300 (5 minutes). */
        public readonly float $pairingPayloadExpiry = 300.0,
    ) {
    }
}

/**
 * Mesh routing settings (spec section 1.2).
 *
 * Matches packages/rs/cairn-p2p/src/config.rs MeshSettings.
 */
final class MeshSettings
{
    public function __construct(
        public readonly bool $meshEnabled = false,
        public readonly int $maxHops = 3,
        public readonly bool $relayWilling = false,
        public readonly int $relayCapacity = 10,
    ) {
    }
}

/**
 * PIN format configuration.
 */
final class PinFormatConfig
{
    public function __construct(
        /** Number of Crockford Base32 characters. Default: 8. */
        public readonly int $length = 8,
        /** Characters per group. Default: 4. */
        public readonly int $groupSize = 4,
        /** Separator between groups. Default: "-". */
        public readonly string $separator = '-',
    ) {
    }
}

/**
 * Top-level configuration object passed at initialization (spec section 1.1).
 *
 * Every field has a sensible default, enabling zero-config usage (Tier 0).
 * PHP 8.2 readonly properties with constructor promotion.
 *
 * Matches packages/rs/cairn-p2p/src/config.rs CairnConfig.
 */
final class CairnConfig
{
    /**
     * @param list<string> $stunServers STUN servers for NAT detection
     * @param list<TurnServer> $turnServers TURN relay servers
     * @param list<string> $signalingServers WebSocket signaling servers
     * @param list<string> $trackerUrls BitTorrent tracker URLs
     * @param list<string> $bootstrapNodes DHT bootstrap nodes
     * @param list<TransportType> $transportPreferences Transport fallback order
     */
    public function __construct(
        public readonly array $stunServers = [
            'stun:stun.l.google.com:19302',
            'stun:stun1.l.google.com:19302',
            'stun:stun.cloudflare.com:3478',
        ],
        public readonly array $turnServers = [],
        public readonly array $signalingServers = [],
        public readonly array $trackerUrls = [],
        public readonly array $bootstrapNodes = [],
        public readonly array $transportPreferences = [
            TransportType::Tcp,
            TransportType::WsTls,
            TransportType::CircuitRelayV2,
        ],
        public readonly ReconnectionPolicy $reconnectionPolicy = new ReconnectionPolicy(),
        public readonly MeshSettings $meshSettings = new MeshSettings(),
        public readonly StorageBackendType $storageBackend = StorageBackendType::Filesystem,
        public readonly string $storagePath = '.cairn',
        public readonly bool $serverMode = false,
        /** Optional app identifier for discovery namespace isolation. */
        public readonly ?string $appIdentifier = null,
        /** PIN format configuration. */
        public readonly PinFormatConfig $pinFormat = new PinFormatConfig(),
        /** Auto-approve all valid pairing requests (kiosk/open mode). */
        public readonly bool $autoApprovePairing = false,
        /** Optional second-layer password for pairing authentication. */
        public readonly ?string $pairingPassword = null,
        /** Optional human-readable message attached to pairing requests. */
        public readonly ?string $pairingMessage = null,
    ) {
    }

    /**
     * Tier 0: fully decentralized, zero-config (mDNS + DHT + public STUN).
     */
    public static function tier0(): self
    {
        return new self();
    }

    /**
     * Tier 1: add signaling server and optional TURN relay.
     *
     * @param list<string> $signalingServers
     * @param list<TurnServer> $turnServers
     */
    public static function tier1(array $signalingServers, array $turnServers = []): self
    {
        return new self(
            signalingServers: $signalingServers,
            turnServers: $turnServers,
        );
    }

    /**
     * Tier 2: self-hosted (signaling + TURN + custom trackers + bootstrap).
     *
     * @param list<string> $signalingServers
     * @param list<TurnServer> $turnServers
     * @param list<string> $trackerUrls
     * @param list<string> $bootstrapNodes
     */
    public static function tier2(
        array $signalingServers,
        array $turnServers = [],
        array $trackerUrls = [],
        array $bootstrapNodes = [],
    ): self {
        return new self(
            signalingServers: $signalingServers,
            turnServers: $turnServers,
            trackerUrls: $trackerUrls,
            bootstrapNodes: $bootstrapNodes,
        );
    }

    /**
     * Tier 3: fully self-hosted with mesh routing enabled.
     */
    public static function tier3(
        array $signalingServers,
        array $turnServers = [],
        array $trackerUrls = [],
        array $bootstrapNodes = [],
        ?MeshSettings $meshSettings = null,
    ): self {
        return new self(
            signalingServers: $signalingServers,
            turnServers: $turnServers,
            trackerUrls: $trackerUrls,
            bootstrapNodes: $bootstrapNodes,
            meshSettings: $meshSettings ?? new MeshSettings(meshEnabled: true),
        );
    }

    /**
     * Default server-mode config (headless, longer expiry, relay-willing).
     */
    public static function defaultServer(): self
    {
        return new self(
            reconnectionPolicy: new ReconnectionPolicy(
                sessionExpiry: 604800.0, // 7 days
                reconnectMaxDuration: PHP_FLOAT_MAX,
            ),
            meshSettings: new MeshSettings(
                meshEnabled: true,
                relayWilling: true,
                relayCapacity: 100,
            ),
            storageBackend: StorageBackendType::Filesystem,
            storagePath: '.cairn-server',
            serverMode: true,
        );
    }

    /**
     * Validate configuration, throwing on invalid settings.
     *
     * @throws CairnException
     */
    public function validate(): void
    {
        // STUN servers must not be empty unless TURN is configured.
        if ($this->stunServers === [] && $this->turnServers === []) {
            throw new CairnException(
                'config validation: stunServers must not be empty unless turnServers are configured',
            );
        }

        // Backoff factor must be > 1.0.
        if ($this->reconnectionPolicy->reconnectBackoffFactor <= 1.0) {
            throw new CairnException(
                'config validation: reconnectBackoffFactor must be greater than 1.0',
            );
        }

        // max_hops must be 1..=10.
        if ($this->meshSettings->maxHops < 1 || $this->meshSettings->maxHops > 10) {
            throw new CairnException(
                'config validation: maxHops must be between 1 and 10',
            );
        }
    }
}
