<?php

declare(strict_types=1);

namespace Cairn\Pairing;

/**
 * Pairing role.
 */
enum PairingRole: string
{
    case Initiator = 'initiator';
    case Responder = 'responder';
}
