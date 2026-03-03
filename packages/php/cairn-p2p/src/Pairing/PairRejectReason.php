<?php

declare(strict_types=1);

namespace Cairn\Pairing;

/**
 * Reason for rejecting a pairing request.
 */
enum PairRejectReason: string
{
    case UserRejected = 'user_rejected';
    case AuthenticationFailed = 'authentication_failed';
    case Timeout = 'timeout';
    case RateLimited = 'rate_limited';
}
