<?php

declare(strict_types=1);

namespace Cairn\Crypto;

/**
 * Output of a single handshake step.
 */
enum StepOutputType
{
    case SendMessage;
    case Complete;
}
