<?php

declare(strict_types=1);

namespace Cairn\Crypto;

use Cairn\Error\CairnException;

/**
 * SPAKE2 password-authenticated key exchange for cairn pairing.
 *
 * Wire-compatible with the RustCrypto spake2 crate v0.4 using Ed25519Group.
 * Uses ext-sodium's Ed25519 point operations (requires libsodium >= 1.0.18).
 *
 * Protocol:
 *   - Side A sends: 0x41 || (x*G + pw*M) — 33 bytes
 *   - Side B sends: 0x42 || (y*G + pw*N) — 33 bytes
 *   - Both derive: SHA256(SHA256(pw) || SHA256(idA) || SHA256(idB) || X || Y || K)
 *
 * M and N are the standard Ed25519 SPAKE2 constants from RustCrypto / python-spake2.
 */
final class Spake2
{
    /**
     * M point (compressed Edwards Y, 32 bytes).
     * Hex: 15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312
     */
    private const M_POINT =
        "\x15\xcf\xd1\x8e\x38\x59\x52\x98\x2b\x6a\x8f\x8c\x78\x54\x96\x3b" .
        "\x58\xe3\x43\x88\xc8\xe6\xda\xe8\x91\xdb\x75\x64\x81\xa0\x23\x12";

    /**
     * N point (compressed Edwards Y, 32 bytes).
     * Hex: f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3
     */
    private const N_POINT =
        "\xf0\x4f\x2e\x7e\xb7\x34\xb2\xa8\xf8\xb4\x72\xea\xf9\xc3\xc6\x32" .
        "\x57\x6a\xc6\x4a\xea\x65\x0b\x49\x6a\x8a\x20\xff\x00\xe5\x83\xc3";

    private const IDENTITY_A = 'cairn-initiator';
    private const IDENTITY_B = 'cairn-responder';

    public readonly SpakeRole $role;
    private string $password;
    private string $scalar; // 32-byte Ed25519 scalar
    private string $passwordScalar; // 32-byte Ed25519 scalar
    private string $myMsg; // 32-byte point (no side prefix)
    private string $outboundMessage; // 33-byte message (side prefix + point)
    private bool $finished = false;

    private function __construct(SpakeRole $role, string $password)
    {
        if (!function_exists('sodium_crypto_core_ed25519_scalar_random')) {
            throw new CairnException('SPAKE2 requires libsodium >= 1.0.18 with Ed25519 support (PHP 8.1+)');
        }

        $this->role = $role;
        $this->password = $password;

        // Generate a random scalar
        $this->scalar = sodium_crypto_core_ed25519_scalar_random();

        // Derive password scalar via HKDF-SHA256 matching RustCrypto
        $this->passwordScalar = self::passwordToScalar($password);

        // T = scalar * G + passwordScalar * (M or N)
        $basePoint = sodium_crypto_scalarmult_ed25519_base_noclamp($this->scalar);

        $blindingGenerator = match ($role) {
            SpakeRole::A => self::M_POINT,
            SpakeRole::B => self::N_POINT,
        };
        $blindingPoint = sodium_crypto_scalarmult_ed25519_noclamp(
            $this->passwordScalar,
            $blindingGenerator,
        );

        $this->myMsg = sodium_crypto_core_ed25519_add($basePoint, $blindingPoint);

        // Prepend side byte: 0x41 for A, 0x42 for B
        $sideByte = match ($role) {
            SpakeRole::A => "\x41",
            SpakeRole::B => "\x42",
        };
        $this->outboundMessage = $sideByte . $this->myMsg;
    }

    public static function startA(string $password): self
    {
        return new self(SpakeRole::A, $password);
    }

    public static function startB(string $password): self
    {
        return new self(SpakeRole::B, $password);
    }

    /**
     * Get the 33-byte outbound message (side prefix + point).
     */
    public function outboundMessage(): string
    {
        return $this->outboundMessage;
    }

    /**
     * Process the peer's 33-byte message and derive the shared secret.
     *
     * @param string $peerMessage 33-byte message (side prefix + Ed25519 point)
     * @return string 32-byte shared secret
     * @throws CairnException
     */
    public function finish(string $peerMessage): string
    {
        if ($this->finished) {
            throw new CairnException('SPAKE2 already finished');
        }

        if (strlen($peerMessage) !== 33) {
            throw new CairnException(sprintf(
                'SPAKE2 peer message must be 33 bytes, got %d',
                strlen($peerMessage),
            ));
        }

        // Validate side byte
        $peerSide = ord($peerMessage[0]);
        if ($this->role === SpakeRole::A && $peerSide !== 0x42) {
            throw new CairnException(sprintf(
                'SPAKE2 bad side byte: expected 0x42, got 0x%02x',
                $peerSide,
            ));
        }
        if ($this->role === SpakeRole::B && $peerSide !== 0x41) {
            throw new CairnException(sprintf(
                'SPAKE2 bad side byte: expected 0x41, got 0x%02x',
                $peerSide,
            ));
        }

        $this->finished = true;

        $peerPointBytes = substr($peerMessage, 1); // 32 bytes

        // Remove blinding: unblinded = peerPoint - passwordScalar * (N or M)
        $peerBlindingGenerator = match ($this->role) {
            SpakeRole::A => self::N_POINT,
            SpakeRole::B => self::M_POINT,
        };
        $peerBlinding = sodium_crypto_scalarmult_ed25519_noclamp(
            $this->passwordScalar,
            $peerBlindingGenerator,
        );
        $unblinded = sodium_crypto_core_ed25519_sub($peerPointBytes, $peerBlinding);

        // K = scalar * unblinded
        $sharedPoint = sodium_crypto_scalarmult_ed25519_noclamp($this->scalar, $unblinded);

        // Transcript hash matching RustCrypto spake2:
        // SHA256(SHA256(pw) || SHA256(idA) || SHA256(idB) || X_msg || Y_msg || K_bytes)
        $pwHash = hash('sha256', $this->password, true);
        $idAHash = hash('sha256', self::IDENTITY_A, true);
        $idBHash = hash('sha256', self::IDENTITY_B, true);

        if ($this->role === SpakeRole::A) {
            $xMsg = $this->myMsg;
            $yMsg = $peerPointBytes;
        } else {
            $xMsg = $peerPointBytes;
            $yMsg = $this->myMsg;
        }

        $transcript = $pwHash . $idAHash . $idBHash . $xMsg . $yMsg . $sharedPoint;
        $result = hash('sha256', $transcript, true);

        // Zero sensitive material
        sodium_memzero($this->scalar);
        sodium_memzero($this->passwordScalar);
        sodium_memzero($this->password);

        return $result;
    }

    /**
     * Derive an Ed25519 scalar from a password using HKDF-SHA256,
     * matching the RustCrypto spake2 crate's hash_to_scalar.
     *
     * HKDF(salt=empty, ikm=password, info="SPAKE2 pw", len=48)
     * Then reverse into 64-byte LE buffer and reduce mod L.
     */
    private static function passwordToScalar(string $password): string
    {
        // HKDF-SHA256: salt=empty, ikm=password, info="SPAKE2 pw", len=48
        $prk = hash_hmac('sha256', $password, '', true);
        // HKDF-Expand with info="SPAKE2 pw", len=48
        $info = 'SPAKE2 pw';
        $t1 = hash_hmac('sha256', $info . "\x01", $prk, true); // 32 bytes
        $t2 = hash_hmac('sha256', $t1 . $info . "\x02", $prk, true); // 32 bytes
        $okm = substr($t1 . $t2, 0, 48);

        // Reverse 48-byte big-endian HKDF output into 64-byte little-endian buffer
        $reducible = str_repeat("\x00", 64);
        for ($i = 0; $i < 48; $i++) {
            $reducible[47 - $i] = $okm[$i];
        }

        // Reduce mod L using libsodium's scalar reduce
        return sodium_crypto_core_ed25519_scalar_reduce($reducible);
    }
}
