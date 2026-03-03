<?php

declare(strict_types=1);

namespace Cairn\Crypto;

/**
 * Supported AEAD cipher suites.
 */
enum CipherSuite: string
{
    case Aes256Gcm = 'aes-256-gcm';
    case ChaCha20Poly1305 = 'chacha20-poly1305';
}
