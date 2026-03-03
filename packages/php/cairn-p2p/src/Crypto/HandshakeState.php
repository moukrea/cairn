<?php

declare(strict_types=1);

namespace Cairn\Crypto;

/**
 * Internal handshake state.
 */
enum HandshakeState
{
    case InitiatorStart;
    case ResponderWaitMsg1;
    case InitiatorWaitMsg2;
    case ResponderWaitMsg3;
    case Complete;
}
