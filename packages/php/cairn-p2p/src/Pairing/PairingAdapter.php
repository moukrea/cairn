<?php

declare(strict_types=1);

namespace Cairn\Pairing;

use Cairn\Error\CairnException;

/**
 * Custom pairing adapter interface.
 *
 * Applications implement this interface for domain-specific pairing flows
 * (e.g., NFC, Bluetooth LE, email-based verification, hardware token).
 *
 * The adapter handles transport-specific encoding/decoding of pairing payloads,
 * while the library handles the PAKE handshake and trust establishment.
 *
 * Matches packages/rs/cairn-p2p/src/pairing/mechanisms/adapter.rs.
 */
interface PairingAdapter
{
    /**
     * Create the pairing payload in the application's chosen format/transport.
     *
     * @param string $data Raw payload data
     * @return string Encoded payload for the custom transport
     * @throws CairnException
     */
    public function generatePayload(string $data): string;

    /**
     * Parse and validate a received pairing payload from the custom transport.
     *
     * @param string $raw Raw bytes received from the transport
     * @return string Decoded payload data
     * @throws CairnException
     */
    public function consumePayload(string $raw): string;

    /**
     * Derive the SPAKE2 password bytes from the custom payload data.
     *
     * Returns the bytes to use as the PAKE password input.
     *
     * @param string $data The payload data
     * @return string PAKE password bytes
     * @throws CairnException
     */
    public function getPakeCredential(string $data): string;

    /**
     * Human-readable name of this mechanism (e.g., "nfc", "bluetooth-le").
     */
    public function name(): string;
}
