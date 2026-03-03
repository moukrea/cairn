<?php

declare(strict_types=1);

namespace Cairn\Mesh;

use Cairn\Crypto\PeerId;

/**
 * A relay session bridging two peers through this node.
 *
 * Relay peers forward opaque encrypted bytes — they cannot read, modify,
 * or forge relayed content. No duration or data limits.
 *
 * Matches packages/rs/cairn-p2p/src/mesh/relay.rs RelaySession.
 */
final class RelaySession
{
    public function __construct(
        /** The unique session identifier. */
        public readonly int $id,
        /** The source peer (requesting the relay). */
        public readonly PeerId $source,
        /** The destination peer (being relayed to). */
        public readonly PeerId $destination,
    ) {
    }
}

/**
 * Manages relay sessions for this peer.
 *
 * Enforces relayWilling and relayCapacity from MeshConfig.
 * Each relay session bridges two streams, forwarding opaque bytes between them.
 *
 * Matches packages/rs/cairn-p2p/src/mesh/relay.rs RelayManager.
 */
final class RelayManager
{
    /** @var array<int, RelaySession> Active relay sessions by ID */
    private array $sessions = [];

    /** Next session ID counter. */
    private int $nextSessionId = 1;

    public function __construct(
        private MeshConfig $config,
    ) {
    }

    /**
     * Request to start a new relay session.
     *
     * Validates that this peer is willing to relay, has capacity, and the
     * destination is not the source.
     *
     * @throws MeshException
     */
    public function requestRelay(PeerId $source, PeerId $destination): int
    {
        if (!$this->config->meshEnabled) {
            throw MeshException::meshDisabled();
        }

        if (!$this->config->relayWilling) {
            throw MeshException::relayNotWilling();
        }

        $active = $this->activeSessionCount();
        if ($active >= $this->config->relayCapacity) {
            throw MeshException::relayCapacityFull($active, $this->config->relayCapacity);
        }

        if ($source->equals($destination)) {
            throw MeshException::relayConnectionFailed('source and destination are the same peer');
        }

        $id = $this->nextSessionId++;

        $this->sessions[$id] = new RelaySession(
            id: $id,
            source: $source,
            destination: $destination,
        );

        return $id;
    }

    /**
     * Close a relay session.
     *
     * @return bool True if the session existed and was closed
     */
    public function closeSession(int $sessionId): bool
    {
        if (isset($this->sessions[$sessionId])) {
            unset($this->sessions[$sessionId]);
            return true;
        }
        return false;
    }

    /**
     * Get the number of active relay sessions.
     */
    public function activeSessionCount(): int
    {
        return count($this->sessions);
    }

    /**
     * Get a relay session by ID.
     */
    public function getSession(int $sessionId): ?RelaySession
    {
        return $this->sessions[$sessionId] ?? null;
    }

    /**
     * Get the remaining relay capacity.
     */
    public function remainingCapacity(): int
    {
        return max(0, $this->config->relayCapacity - $this->activeSessionCount());
    }

    /**
     * Check whether this peer is willing to relay.
     */
    public function isWilling(): bool
    {
        return $this->config->relayWilling;
    }

    /**
     * Update the mesh configuration.
     */
    public function updateConfig(MeshConfig $config): void
    {
        $this->config = $config;
    }
}
