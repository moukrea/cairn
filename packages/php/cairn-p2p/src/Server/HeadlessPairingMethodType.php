<?php

declare(strict_types=1);

namespace Cairn\Server;

/**
 * Headless pairing method types.
 */
enum HeadlessPairingMethodType: string
{
    case PreSharedKey = 'psk';
    case PinCode = 'pin';
    case PairingLink = 'link';
    case QrCode = 'qr';
}
