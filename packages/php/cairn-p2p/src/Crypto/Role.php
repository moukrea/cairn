<?php

declare(strict_types=1);

namespace Cairn\Crypto;

/**
 * Noise XX handshake role.
 */
enum Role
{
    case Initiator;
    case Responder;
}
