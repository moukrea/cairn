<?php

declare(strict_types=1);

namespace Cairn\Pairing;

use Cairn\Error\CairnException;

/**
 * QR code pairing mechanism.
 *
 * Generates a CBOR binary payload suitable for QR code encoding at EC Level M.
 * Maximum payload size is 256 bytes, fitting within QR Version 14 (73x73 modules).
 *
 * Uses endroid/qr-code for QR image generation when available.
 *
 * Matches packages/rs/cairn-p2p/src/pairing/mechanisms/qr.rs.
 */
final class QrCode
{
    /** Maximum payload size for QR code encoding. */
    public const MAX_PAYLOAD_SIZE = 256;

    /** Default TTL in seconds (5 minutes). */
    public const DEFAULT_TTL = 300;

    private function __construct()
    {
    }

    /**
     * Generate a CBOR payload from a PairingPayload.
     *
     * @throws CairnException If payload exceeds MAX_PAYLOAD_SIZE
     */
    public static function generatePayload(PairingPayload $payload): string
    {
        $cbor = $payload->toCbor();

        if (strlen($cbor) > self::MAX_PAYLOAD_SIZE) {
            throw new CairnException(sprintf(
                'QR payload exceeds maximum size of %d bytes (actual: %d)',
                self::MAX_PAYLOAD_SIZE,
                strlen($cbor),
            ));
        }

        return $cbor;
    }

    /**
     * Parse a CBOR payload from a scanned QR code.
     *
     * @throws CairnException
     */
    public static function consumePayload(string $raw): PairingPayload
    {
        if (strlen($raw) > self::MAX_PAYLOAD_SIZE) {
            throw new CairnException(sprintf(
                'QR payload exceeds maximum size of %d bytes (actual: %d)',
                self::MAX_PAYLOAD_SIZE,
                strlen($raw),
            ));
        }

        $payload = PairingPayload::fromCbor($raw);

        if ($payload->isExpired()) {
            throw new CairnException('QR pairing payload has expired');
        }

        return $payload;
    }

    /**
     * Generate a QR code image as a PNG string using endroid/qr-code.
     *
     * Requires endroid/qr-code to be installed. Uses binary encoding mode
     * with Error Correction Level M (15% recovery).
     *
     * @param PairingPayload $payload The pairing payload to encode
     * @return string PNG image data
     * @throws CairnException
     */
    public static function toPng(PairingPayload $payload): string
    {
        $cbor = self::generatePayload($payload);

        if (!class_exists(\Endroid\QrCode\QrCode::class)) {
            throw new CairnException('endroid/qr-code package is required for QR image generation');
        }

        /** @var \Endroid\QrCode\QrCode $qr */
        $qr = new \Endroid\QrCode\QrCode($cbor);
        $qr->setEncoding(new \Endroid\QrCode\Encoding\Encoding('ISO-8859-1'));
        $qr->setErrorCorrectionLevel(\Endroid\QrCode\ErrorCorrectionLevel::Medium);

        $writer = new \Endroid\QrCode\Writer\PngWriter();
        $result = $writer->write($qr);

        return $result->getString();
    }
}
