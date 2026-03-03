<?php

declare(strict_types=1);

namespace Cairn\Pairing;

/**
 * Pairing session state.
 */
enum PairingState: string
{
    case Idle = 'idle';
    case AwaitingPakeExchange = 'awaiting_pake_exchange';
    case AwaitingVerification = 'awaiting_verification';
    case AwaitingConfirmation = 'awaiting_confirmation';
    case Completed = 'completed';
    case Failed = 'failed';
}
