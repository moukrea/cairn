<?php

declare(strict_types=1);

namespace Cairn\Crypto;

use Cairn\Error\CairnException;

/**
 * Result of a completed Noise XX handshake.
 */
final class HandshakeResult
{
    public function __construct(
        /** Shared symmetric key for session encryption (32 bytes). */
        public readonly string $sessionKey,
        /** Remote peer's static public key (Ed25519, 32 bytes). */
        public readonly string $remoteStatic,
        /** Handshake transcript hash for SAS derivation (32 bytes). */
        public readonly string $transcriptHash,
    ) {
    }
}

/**
 * Output from a handshake step.
 */
final class StepOutput
{
    private function __construct(
        public readonly StepOutputType $type,
        public readonly ?string $message,
        public readonly ?HandshakeResult $result,
    ) {
    }

    public static function sendMessage(string $message): self
    {
        return new self(StepOutputType::SendMessage, $message, null);
    }

    public static function complete(HandshakeResult $result): self
    {
        return new self(StepOutputType::Complete, null, $result);
    }
}

/**
 * Noise XX handshake state machine.
 *
 * Protocol: Noise_XX_25519_ChaChaPoly_SHA256
 * Pattern:
 *   -> e                 (message 1)
 *   <- e, ee, s, es      (message 2)
 *   -> s, se             (message 3)
 *
 * Matches the Rust NoiseXXHandshake in packages/rs/cairn-p2p/src/crypto/noise.rs.
 */
final class NoiseXXHandshake
{
    private const PROTOCOL_NAME = 'Noise_XX_25519_ChaChaPoly_SHA256';
    private const DH_KEY_SIZE = 32;
    private const ED25519_PUB_SIZE = 32;
    private const TAG_SIZE = 16;
    private const ZERO_NONCE = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    /** Emoji table for SAS derivation (64 entries). */
    public const EMOJI_TABLE = [
        'dog', 'cat', 'fish', 'bird', 'bear', 'lion', 'wolf', 'fox',
        'deer', 'owl', 'bee', 'ant', 'star', 'moon', 'sun', 'fire',
        'tree', 'leaf', 'rose', 'wave', 'rain', 'snow', 'bolt', 'wind',
        'rock', 'gem', 'bell', 'key', 'lock', 'flag', 'book', 'pen',
        'cup', 'hat', 'shoe', 'ring', 'cake', 'gift', 'lamp', 'gear',
        'ship', 'car', 'bike', 'drum', 'horn', 'harp', 'dice', 'coin',
        'map', 'tent', 'crown', 'sword', 'shield', 'bow', 'axe', 'hammer',
        'anchor', 'wheel', 'clock', 'heart', 'skull', 'ghost', 'robot', 'alien',
    ];

    private HandshakeState $state;
    private Identity $localIdentity;
    private string $localStaticX25519Secret;
    private ?string $localEphemeralSecret = null;
    private ?string $localEphemeralPub = null;
    private ?string $remoteEphemeral = null;
    private ?string $remoteStatic = null;
    private string $chainingKey;
    private string $handshakeHash;
    private ?string $currentKey = null;
    private ?string $pakeSecret = null;
    private ?HandshakeResult $cachedResult = null;

    public function __construct(Role $role, Identity $identity)
    {
        $this->localIdentity = $identity;
        $this->localStaticX25519Secret = $identity->toX25519SecretKey();

        // Initialize handshake hash from protocol name (Noise spec section 5.2)
        $protocolName = self::PROTOCOL_NAME;
        if (strlen($protocolName) <= 32) {
            $this->handshakeHash = str_pad($protocolName, 32, "\x00");
        } else {
            $this->handshakeHash = hash('sha256', $protocolName, true);
        }

        $this->chainingKey = $this->handshakeHash;

        $this->state = match ($role) {
            Role::Initiator => HandshakeState::InitiatorStart,
            Role::Responder => HandshakeState::ResponderWaitMsg1,
        };
    }

    /**
     * Set a SPAKE2-derived pre-shared key for authentication.
     */
    public function withPakeSecret(string $secret): self
    {
        $this->pakeSecret = $secret;
        return $this;
    }

    /**
     * Process the next handshake step.
     *
     * @throws CairnException
     */
    public function step(?string $input = null): StepOutput
    {
        return match ($this->state) {
            HandshakeState::InitiatorStart => $this->initiatorSendMsg1($input),
            HandshakeState::ResponderWaitMsg1 => $this->responderRecvMsg1SendMsg2($input),
            HandshakeState::InitiatorWaitMsg2 => $this->initiatorRecvMsg2SendMsg3($input),
            HandshakeState::ResponderWaitMsg3 => $this->responderRecvMsg3($input),
            HandshakeState::Complete => throw new CairnException('handshake already complete'),
        };
    }

    /**
     * Get the cached handshake result (initiator only, after sending msg3).
     *
     * @throws CairnException
     */
    public function result(): HandshakeResult
    {
        if ($this->cachedResult === null) {
            throw new CairnException('handshake not yet complete');
        }
        return $this->cachedResult;
    }

    // --- Message 1: -> e ---

    private function initiatorSendMsg1(?string $input): StepOutput
    {
        if ($input !== null) {
            throw new CairnException('initiator start expects no input');
        }

        // Generate ephemeral keypair
        $ephKeypair = sodium_crypto_box_keypair();
        $this->localEphemeralSecret = sodium_crypto_box_secretkey($ephKeypair);
        $ephPub = sodium_crypto_box_publickey($ephKeypair);
        $this->localEphemeralPub = $ephPub;

        // Convert to X25519 base point multiplication format
        // sodium_crypto_box uses X25519 internally
        $this->mixHash($ephPub);

        $this->state = HandshakeState::InitiatorWaitMsg2;
        return StepOutput::sendMessage($ephPub);
    }

    // --- Message 2: <- e, ee, s, es ---

    private function responderRecvMsg1SendMsg2(?string $msg1): StepOutput
    {
        if ($msg1 === null) {
            throw new CairnException('responder expects message 1 input');
        }

        if (strlen($msg1) !== self::DH_KEY_SIZE) {
            throw new CairnException(sprintf(
                'message 1 invalid length: expected %d, got %d',
                self::DH_KEY_SIZE,
                strlen($msg1),
            ));
        }

        $this->remoteEphemeral = $msg1;
        $this->mixHash($msg1);

        $msg2 = '';

        // e: generate responder ephemeral
        $ephKeypair = sodium_crypto_box_keypair();
        $this->localEphemeralSecret = sodium_crypto_box_secretkey($ephKeypair);
        $ephPub = sodium_crypto_box_publickey($ephKeypair);
        $this->localEphemeralPub = $ephPub;

        $this->mixHash($ephPub);
        $msg2 .= $ephPub;

        // ee: DH(responder_ephemeral, initiator_ephemeral)
        $eeShared = sodium_crypto_scalarmult($this->localEphemeralSecret, $this->remoteEphemeral);
        $this->mixKey($eeShared);

        // s: encrypt and send static Ed25519 public key
        $staticPubBytes = $this->localIdentity->publicKey();
        $encryptedStatic = $this->encryptAndHash($staticPubBytes);
        $msg2 .= $encryptedStatic;

        // es: DH(responder_static_x25519, initiator_ephemeral)
        $esShared = sodium_crypto_scalarmult($this->localStaticX25519Secret, $this->remoteEphemeral);
        $this->mixKey($esShared);

        // Encrypt empty payload
        $encryptedPayload = $this->encryptAndHash('');
        $msg2 .= $encryptedPayload;

        $this->state = HandshakeState::ResponderWaitMsg3;
        return StepOutput::sendMessage($msg2);
    }

    // --- Initiator: recv message 2, send message 3 ---

    private function initiatorRecvMsg2SendMsg3(?string $msg2): StepOutput
    {
        if ($msg2 === null) {
            throw new CairnException('initiator expects message 2 input');
        }

        $minLen = self::DH_KEY_SIZE + (self::ED25519_PUB_SIZE + self::TAG_SIZE) + self::TAG_SIZE;
        if (strlen($msg2) < $minLen) {
            throw new CairnException(sprintf(
                'message 2 too short: expected at least %d, got %d',
                $minLen,
                strlen($msg2),
            ));
        }

        $offset = 0;

        // e: responder ephemeral
        $remoteEphemeral = substr($msg2, $offset, self::DH_KEY_SIZE);
        $this->mixHash($remoteEphemeral);
        $offset += self::DH_KEY_SIZE;
        $this->remoteEphemeral = $remoteEphemeral;

        // ee: DH(initiator_ephemeral, responder_ephemeral)
        if ($this->localEphemeralSecret === null) {
            throw new CairnException('missing local ephemeral key');
        }
        $eeShared = sodium_crypto_scalarmult($this->localEphemeralSecret, $remoteEphemeral);
        $this->mixKey($eeShared);

        // s: decrypt responder's static public key
        $encryptedStatic = substr($msg2, $offset, self::ED25519_PUB_SIZE + self::TAG_SIZE);
        $staticPubBytes = $this->decryptAndHash($encryptedStatic);
        $offset += self::ED25519_PUB_SIZE + self::TAG_SIZE;

        if (strlen($staticPubBytes) !== self::ED25519_PUB_SIZE) {
            throw new CairnException('decrypted static key wrong size');
        }

        // Convert remote Ed25519 public key to X25519 for DH
        $remoteStaticX25519 = sodium_crypto_sign_ed25519_pk_to_curve25519($staticPubBytes);
        $this->remoteStatic = $staticPubBytes;

        // es: DH(initiator_ephemeral, responder_static_x25519)
        $esShared = sodium_crypto_scalarmult($this->localEphemeralSecret, $remoteStaticX25519);
        $this->mixKey($esShared);

        // Decrypt payload from message 2
        $encryptedPayload = substr($msg2, $offset);
        $this->decryptAndHash($encryptedPayload);

        // Build message 3: -> s, se
        $msg3 = '';

        // s: encrypt initiator's static Ed25519 public key
        $ourStaticPubBytes = $this->localIdentity->publicKey();
        $encryptedOurStatic = $this->encryptAndHash($ourStaticPubBytes);
        $msg3 .= $encryptedOurStatic;

        // se: DH(initiator_static_x25519, responder_ephemeral)
        $seShared = sodium_crypto_scalarmult($this->localStaticX25519Secret, $remoteEphemeral);
        $this->mixKey($seShared);

        // Mix in PAKE secret if present
        if ($this->pakeSecret !== null) {
            $this->mixKey($this->pakeSecret);
        }

        // Encrypt empty payload for message 3
        $encryptedPayload = $this->encryptAndHash('');
        $msg3 .= $encryptedPayload;

        // Derive session key
        $sessionKey = $this->deriveSessionKey();

        $this->cachedResult = new HandshakeResult(
            sessionKey: $sessionKey,
            remoteStatic: $staticPubBytes,
            transcriptHash: $this->handshakeHash,
        );

        $this->state = HandshakeState::Complete;
        return StepOutput::sendMessage($msg3);
    }

    // --- Message 3: responder receives -> s, se ---

    private function responderRecvMsg3(?string $msg3): StepOutput
    {
        if ($msg3 === null) {
            throw new CairnException('responder expects message 3 input');
        }

        $minLen = (self::ED25519_PUB_SIZE + self::TAG_SIZE) + self::TAG_SIZE;
        if (strlen($msg3) < $minLen) {
            throw new CairnException(sprintf(
                'message 3 too short: expected at least %d, got %d',
                $minLen,
                strlen($msg3),
            ));
        }

        $offset = 0;

        // s: decrypt initiator's static public key
        $encryptedStatic = substr($msg3, $offset, self::ED25519_PUB_SIZE + self::TAG_SIZE);
        $staticPubBytes = $this->decryptAndHash($encryptedStatic);
        $offset += self::ED25519_PUB_SIZE + self::TAG_SIZE;

        if (strlen($staticPubBytes) !== self::ED25519_PUB_SIZE) {
            throw new CairnException('decrypted static key wrong size');
        }

        // Convert remote Ed25519 to X25519
        $remoteStaticX25519 = sodium_crypto_sign_ed25519_pk_to_curve25519($staticPubBytes);
        $this->remoteStatic = $staticPubBytes;

        // se: DH(responder_ephemeral, initiator_static_x25519)
        if ($this->localEphemeralSecret === null) {
            throw new CairnException('missing local ephemeral for se DH');
        }
        $seShared = sodium_crypto_scalarmult($this->localEphemeralSecret, $remoteStaticX25519);
        $this->mixKey($seShared);

        // Mix in PAKE secret if present
        if ($this->pakeSecret !== null) {
            $this->mixKey($this->pakeSecret);
        }

        // Decrypt payload
        $encryptedPayload = substr($msg3, $offset);
        $this->decryptAndHash($encryptedPayload);

        // Derive session key
        $sessionKey = $this->deriveSessionKey();

        $this->state = HandshakeState::Complete;

        return StepOutput::complete(new HandshakeResult(
            sessionKey: $sessionKey,
            remoteStatic: $staticPubBytes,
            transcriptHash: $this->handshakeHash,
        ));
    }

    // --- Noise symmetric state operations ---

    private function mixKey(string $inputKeyMaterial): void
    {
        $output = Kdf::hkdfSha256($inputKeyMaterial, '', 64, $this->chainingKey);
        $this->chainingKey = substr($output, 0, 32);
        $this->currentKey = substr($output, 32, 32);
    }

    private function mixHash(string $data): void
    {
        $this->handshakeHash = hash('sha256', $this->handshakeHash . $data, true);
    }

    private function encryptAndHash(string $plaintext): string
    {
        if ($this->currentKey === null) {
            throw new CairnException('no encryption key available (mixKey not called)');
        }

        $ciphertext = Aead::encrypt(
            CipherSuite::ChaCha20Poly1305,
            $this->currentKey,
            self::ZERO_NONCE,
            $plaintext,
            $this->handshakeHash,
        );

        $this->mixHash($ciphertext);
        return $ciphertext;
    }

    private function decryptAndHash(string $ciphertext): string
    {
        if ($this->currentKey === null) {
            throw new CairnException('no decryption key available (mixKey not called)');
        }

        $hashBefore = $this->handshakeHash;
        $this->mixHash($ciphertext);

        return Aead::decrypt(
            CipherSuite::ChaCha20Poly1305,
            $this->currentKey,
            self::ZERO_NONCE,
            $ciphertext,
            $hashBefore,
        );
    }

    private function deriveSessionKey(): string
    {
        return Kdf::hkdfSha256($this->chainingKey, Kdf::HKDF_INFO_SESSION_KEY);
    }

    /**
     * Derive a 6-digit numeric SAS from the handshake transcript hash.
     */
    public static function deriveNumericSas(string $transcriptHash): string
    {
        $derived = Kdf::hkdfSha256($transcriptHash, Kdf::HKDF_INFO_SAS, 4);
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('N', $derived);
        $value = $unpacked[1] % 1_000_000;
        return sprintf('%06d', $value);
    }

    /**
     * Derive an emoji SAS from the handshake transcript hash.
     *
     * @return list<string> Four emoji names from the EMOJI_TABLE
     */
    public static function deriveEmojiSas(string $transcriptHash): array
    {
        $derived = Kdf::hkdfSha256($transcriptHash, Kdf::HKDF_INFO_SAS, 4);
        $emojis = [];
        for ($i = 0; $i < 4; $i++) {
            $index = ord($derived[$i]) % 64;
            $emojis[] = self::EMOJI_TABLE[$index];
        }
        return $emojis;
    }
}
