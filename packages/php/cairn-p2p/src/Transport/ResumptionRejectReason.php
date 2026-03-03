<?php

declare(strict_types=1);

namespace Cairn\Transport;

/**
 * Reasons a session resumption can be rejected.
 */
enum ResumptionRejectReason: string
{
    case SessionNotFound = 'session_not_found';
    case SessionExpired = 'session_expired';
    case InvalidProof = 'invalid_proof';
    case ReplayDetected = 'replay_detected';

    public function label(): string
    {
        return match ($this) {
            self::SessionNotFound => 'session not found',
            self::SessionExpired => 'session expired',
            self::InvalidProof => 'invalid proof',
            self::ReplayDetected => 'replay detected',
        };
    }
}
