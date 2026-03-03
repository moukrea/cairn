<?php

declare(strict_types=1);

namespace Cairn\Pairing;

/**
 * Pairing flow type.
 */
enum PairingFlowType: string
{
    /** Verification-only (SAS) — uses Noise XX handshake, then out-of-band verification. */
    case Standard = 'standard';
    /** Self-bootstrapping (QR, pin, link, PSK) — uses SPAKE2 PAKE. */
    case Initiation = 'initiation';
}
