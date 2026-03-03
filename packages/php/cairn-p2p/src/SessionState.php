<?php

declare(strict_types=1);

namespace Cairn;

/**
 * Connection lifecycle states per spec section 2.
 *
 * Connected -> Unstable -> Disconnected -> Reconnecting -> Suspended
 *     ^                                            |                |
 *     |                                            v                v
 *     +------------- Reconnected <-----------------+                |
 *     |                                                             |
 *     +------------------------- Failed <---------------------------+
 *
 * Matches packages/rs/cairn-p2p/src/session/mod.rs SessionState.
 */
enum SessionState: string
{
    /** Active, healthy connection. Data flows normally. */
    case Connected = 'connected';
    /** Degradation detected (high latency, packet loss). Proactively probing alternatives. */
    case Unstable = 'unstable';
    /** Transport lost. Immediately enters reconnection. */
    case Disconnected = 'disconnected';
    /** Actively attempting to re-establish transport. */
    case Reconnecting = 'reconnecting';
    /** Reconnection paused (exponential backoff). Retries periodically. */
    case Suspended = 'suspended';
    /** Transport re-established, session resumed, sequence state synchronized. */
    case Reconnected = 'reconnected';
    /** Max retry budget exhausted or session expired. */
    case Failed = 'failed';

    public function label(): string
    {
        return match ($this) {
            self::Connected => 'Connected',
            self::Unstable => 'Unstable',
            self::Disconnected => 'Disconnected',
            self::Reconnecting => 'Reconnecting',
            self::Suspended => 'Suspended',
            self::Reconnected => 'Reconnected',
            self::Failed => 'Failed',
        };
    }
}
