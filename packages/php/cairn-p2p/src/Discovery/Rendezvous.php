<?php

declare(strict_types=1);

namespace Cairn\Discovery;

use Cairn\Crypto\Kdf;
use Cairn\Error\CairnException;

/**
 * HKDF info string for rendezvous ID derivation from pairing secrets.
 */
const HKDF_INFO_RENDEZVOUS = 'cairn-rendezvous-v1';

/**
 * HKDF info string for pairing-bootstrapped rendezvous ID derivation.
 */
const HKDF_INFO_PAIRING_RENDEZVOUS = 'cairn-pairing-rendezvous-v1';

/**
 * HKDF info string for deriving the epoch offset from a pairing secret.
 */
const HKDF_INFO_EPOCH_OFFSET = 'cairn-epoch-offset-v1';

/**
 * A rendezvous identifier (32 bytes, opaque).
 *
 * Matches packages/rs/cairn-p2p/src/discovery/rendezvous.rs RendezvousId.
 */
final class RendezvousId
{
    public function __construct(
        public readonly string $bytes,
    ) {
        if (strlen($bytes) !== 32) {
            throw new CairnException('RendezvousId must be exactly 32 bytes');
        }
    }

    /**
     * Encode as hex string for display and use as topic/key names.
     */
    public function toHex(): string
    {
        return bin2hex($this->bytes);
    }

    /**
     * Truncate to 20 bytes for use as a BitTorrent info_hash.
     */
    public function toInfoHash(): string
    {
        return substr($this->bytes, 0, 20);
    }
}

/**
 * Configuration for rendezvous ID rotation.
 *
 * Matches packages/rs/cairn-p2p/src/discovery/rendezvous.rs RotationConfig.
 */
final class RotationConfig
{
    public function __construct(
        /** Rotation interval in seconds. Default: 24 hours. */
        public readonly int $rotationInterval = 86400,
        /** Overlap window centered on epoch boundary in seconds. Default: 1 hour. */
        public readonly int $overlapWindow = 3600,
        /** Clock tolerance in seconds. Default: 5 minutes. */
        public readonly int $clockTolerance = 300,
    ) {
    }
}

/**
 * Derive a rendezvous ID from a pairing secret and epoch number.
 *
 * Uses HKDF-SHA256 with info string "cairn-rendezvous-v1". The epoch number
 * is encoded as big-endian uint64 and used as the HKDF salt.
 *
 * @throws CairnException
 */
function deriveRendezvousId(string $pairingSecret, int $epoch): RendezvousId
{
    $salt = pack('J', $epoch); // big-endian uint64
    $bytes = Kdf::hkdfSha256($pairingSecret, HKDF_INFO_RENDEZVOUS, 32, $salt);
    return new RendezvousId($bytes);
}

/**
 * Derive a pairing-bootstrapped rendezvous ID from PAKE credentials and a nonce.
 *
 * Used for initial discovery before a pairing secret exists (pin code, QR code,
 * pairing link). Only used for the initial connection.
 *
 * @throws CairnException
 */
function derivePairingRendezvousId(string $pakeCredential, string $nonce): RendezvousId
{
    $bytes = Kdf::hkdfSha256($pakeCredential, HKDF_INFO_PAIRING_RENDEZVOUS, 32, $nonce);
    return new RendezvousId($bytes);
}

/**
 * Derive the epoch offset from a pairing secret.
 *
 * This makes the epoch boundary unpredictable to observers since it differs
 * per pairing relationship.
 *
 * @throws CairnException
 */
function deriveEpochOffset(string $pairingSecret): int
{
    $bytes = Kdf::hkdfSha256($pairingSecret, HKDF_INFO_EPOCH_OFFSET, 8);
    /** @var array{1: int} $unpacked */
    $unpacked = unpack('J', $bytes);
    return $unpacked[1];
}

/**
 * Compute the epoch number for a given pairing secret and timestamp.
 *
 * The epoch boundary is offset by a value derived from the pairing secret,
 * making it unpredictable to observers.
 *
 * @throws CairnException
 */
function computeEpoch(string $pairingSecret, int $rotationInterval, int $timestampSecs): int
{
    if ($rotationInterval <= 0) {
        throw new CairnException('rotation interval must be > 0');
    }
    $offset = deriveEpochOffset($pairingSecret);
    // Use unsigned wrapping add semantics
    $adjusted = ($timestampSecs + $offset) & 0x7FFFFFFFFFFFFFFF;
    return intdiv($adjusted, $rotationInterval);
}

/**
 * Compute the current epoch number using the system clock.
 *
 * @throws CairnException
 */
function currentEpoch(string $pairingSecret, int $rotationInterval): int
{
    return computeEpoch($pairingSecret, $rotationInterval, time());
}

/**
 * Determine which rendezvous IDs are active at a given timestamp.
 *
 * Outside the overlap window: returns only the current epoch's ID.
 * Inside the overlap window: returns both current and previous/next epoch's IDs.
 *
 * @return list<RendezvousId>
 * @throws CairnException
 */
function activeRendezvousIdsAt(
    string $pairingSecret,
    RotationConfig $config,
    int $timestampSecs,
): array {
    $interval = $config->rotationInterval;
    if ($interval <= 0) {
        throw new CairnException('rotation interval must be > 0');
    }

    $offset = deriveEpochOffset($pairingSecret);
    $adjusted = ($timestampSecs + $offset) & 0x7FFFFFFFFFFFFFFF;
    $currentEpoch = intdiv($adjusted, $interval);
    $positionInEpoch = $adjusted % $interval;

    $halfOverlap = intdiv($config->overlapWindow, 2) + $config->clockTolerance;

    $currentId = deriveRendezvousId($pairingSecret, $currentEpoch);

    // Check if we're in the overlap window near the epoch boundary.
    $inOverlap = $positionInEpoch < $halfOverlap
        || $positionInEpoch > ($interval - $halfOverlap);

    if ($inOverlap && $currentEpoch > 0) {
        $otherEpoch = $positionInEpoch < $halfOverlap
            ? $currentEpoch - 1
            : $currentEpoch + 1;
        $otherId = deriveRendezvousId($pairingSecret, $otherEpoch);
        return [$currentId, $otherId];
    }

    return [$currentId];
}

/**
 * Determine which rendezvous IDs are active right now using the system clock.
 *
 * @return list<RendezvousId>
 * @throws CairnException
 */
function activeRendezvousIds(string $pairingSecret, RotationConfig $config): array
{
    return activeRendezvousIdsAt($pairingSecret, $config, time());
}
