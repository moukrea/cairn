<?php

declare(strict_types=1);

namespace Cairn\Error;

/**
 * Base exception for all cairn errors.
 *
 * All cairn error types extend this class. Each subclass returns an
 * ErrorBehavior indicating the recommended recovery action.
 *
 * Matches packages/rs/cairn-p2p/src/error.rs CairnError.
 */
class CairnException extends \RuntimeException
{
    /**
     * Returns the recommended recovery action for this error.
     *
     * Override in subclasses to return specific behaviors.
     */
    public function behavior(): ErrorBehavior
    {
        return ErrorBehavior::Abort;
    }
}

/**
 * All transports exhausted -- no connectivity path available.
 * Behavior: RETRY with different transport configuration.
 */
final class TransportExhausted extends CairnException
{
    public readonly string $suggestion;

    public function __construct(
        public readonly string $details,
        string $suggestion = '',
    ) {
        $this->suggestion = $suggestion ?: 'deploy the cairn signaling server and/or TURN relay';
        parent::__construct("all transports exhausted: {$details}. Suggestion: {$this->suggestion}");
    }

    public function suggestion(): string
    {
        return $this->suggestion;
    }

    public function behavior(): ErrorBehavior
    {
        return ErrorBehavior::Retry;
    }
}

/**
 * Session expired after the configured duration.
 * Behavior: RECONNECT (re-establish session, no re-pairing).
 */
final class SessionExpired extends CairnException
{
    public function __construct(
        public readonly string $sessionId,
        public readonly float $expiryDuration,
    ) {
        parent::__construct("session expired after {$expiryDuration}s");
    }

    public function behavior(): ErrorBehavior
    {
        return ErrorBehavior::Reconnect;
    }
}

/**
 * Peer unreachable at any rendezvous point within timeout.
 * Behavior: WAIT (background poll for availability).
 */
final class PeerUnreachable extends CairnException
{
    public function __construct(
        public readonly string $peerId,
        public readonly float $timeout,
    ) {
        parent::__construct("peer {$peerId} unreachable at any rendezvous point within {$timeout}s");
    }

    public function behavior(): ErrorBehavior
    {
        return ErrorBehavior::Wait;
    }
}

/**
 * Cryptographic authentication failed (possible key compromise).
 * Behavior: ABORT (manual intervention required).
 */
final class AuthenticationFailed extends CairnException
{
    public function __construct(
        public readonly string $sessionId,
    ) {
        parent::__construct("authentication failed for session {$sessionId}: cryptographic verification failed (possible key compromise)");
    }

    public function behavior(): ErrorBehavior
    {
        return ErrorBehavior::Abort;
    }
}

/**
 * Pairing rejected by the remote peer.
 * Behavior: INFORM (user needs to know).
 */
final class PairingRejected extends CairnException
{
    public function __construct(
        public readonly string $peerId,
    ) {
        parent::__construct("pairing rejected by remote peer {$peerId}");
    }

    public function behavior(): ErrorBehavior
    {
        return ErrorBehavior::Inform;
    }
}

/**
 * Pairing payload expired. Generate a new payload to retry.
 * Behavior: REGENERATE.
 */
final class PairingExpired extends CairnException
{
    public function __construct(
        public readonly float $expiry,
    ) {
        parent::__construct("pairing payload expired after {$expiry}s. Generate a new payload to retry.");
    }

    public function behavior(): ErrorBehavior
    {
        return ErrorBehavior::ReGenerate;
    }
}

/**
 * No mesh route found to the target peer.
 * Behavior: WAIT (keep looking for route).
 */
final class MeshRouteNotFound extends CairnException
{
    public readonly string $suggestion;

    public function __construct(
        public readonly string $peerId,
        string $suggestion = '',
    ) {
        $this->suggestion = $suggestion ?: 'try a direct connection or wait for mesh route discovery';
        parent::__construct("no mesh route found to {$peerId}: {$this->suggestion}");
    }

    public function suggestion(): string
    {
        return $this->suggestion;
    }

    public function behavior(): ErrorBehavior
    {
        return ErrorBehavior::Wait;
    }
}

/**
 * Protocol version mismatch between local and remote peers.
 * Behavior: ABORT.
 */
final class VersionMismatch extends CairnException
{
    public readonly string $suggestion;

    public function __construct(
        public readonly string $localVersion,
        public readonly string $remoteVersion,
        string $suggestion = '',
    ) {
        $this->suggestion = $suggestion ?: 'peer needs to update to a compatible cairn version';
        parent::__construct(
            "protocol version mismatch: local {$localVersion}, remote {$remoteVersion}. {$this->suggestion}",
        );
    }

    public function suggestion(): string
    {
        return $this->suggestion;
    }

    public function behavior(): ErrorBehavior
    {
        return ErrorBehavior::Abort;
    }
}
