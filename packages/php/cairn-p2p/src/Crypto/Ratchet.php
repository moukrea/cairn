<?php

declare(strict_types=1);

namespace Cairn\Crypto;

use Cairn\Error\CairnException;

/**
 * Configuration for the Double Ratchet.
 */
final class RatchetConfig
{
    public function __construct(
        public readonly int $maxSkip = 100,
        public readonly CipherSuite $cipher = CipherSuite::Aes256Gcm,
    ) {
    }
}

/**
 * Header sent alongside each Double Ratchet encrypted message.
 */
final class RatchetHeader
{
    public function __construct(
        /** Sender's current DH ratchet public key (32 bytes). */
        public readonly string $dhPublic,
        /** Number of messages in the previous sending chain. */
        public readonly int $prevChainLen,
        /** Message number in the current sending chain. */
        public readonly int $msgNum,
    ) {
    }

    /**
     * Serialize the header to JSON for use as AEAD associated data.
     * Matches the Rust serde_json serialization.
     */
    public function toJson(): string
    {
        return json_encode([
            'dh_public' => array_values(unpack('C*', $this->dhPublic)),
            'prev_chain_len' => $this->prevChainLen,
            'msg_num' => $this->msgNum,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * Deserialize a header from JSON.
     *
     * @throws CairnException
     */
    public static function fromJson(string $json): self
    {
        try {
            /** @var array{dh_public: list<int>, prev_chain_len: int, msg_num: int} $data */
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new CairnException('invalid ratchet header JSON: ' . $e->getMessage(), 0, $e);
        }

        $dhPublic = pack('C*', ...$data['dh_public']);

        return new self(
            dhPublic: $dhPublic,
            prevChainLen: $data['prev_chain_len'],
            msgNum: $data['msg_num'],
        );
    }
}

/**
 * Signal Double Ratchet session.
 *
 * Combines DH ratcheting (X25519), root chain KDF, and symmetric chain
 * KDF to provide forward secrecy and break-in recovery for each message.
 *
 * Matches the Rust DoubleRatchet in packages/rs/cairn-p2p/src/crypto/ratchet.rs.
 */
final class DoubleRatchet
{
    private string $dhSelfSecret;
    private string $dhSelfPublic;
    private ?string $dhRemote;
    private string $rootKey;
    private ?string $chainKeySend;
    private ?string $chainKeyRecv;
    private int $msgNumSend;
    private int $msgNumRecv;
    private int $prevChainLen;
    /** @var array<string, string> Skipped message keys: "$dhPublicHex:$msgNum" -> 32-byte key */
    private array $skippedKeys;
    private RatchetConfig $config;

    private function __construct(RatchetConfig $config)
    {
        $this->config = $config;
        $this->dhRemote = null;
        $this->chainKeySend = null;
        $this->chainKeyRecv = null;
        $this->msgNumSend = 0;
        $this->msgNumRecv = 0;
        $this->prevChainLen = 0;
        $this->skippedKeys = [];
        $this->dhSelfSecret = '';
        $this->dhSelfPublic = '';
        $this->rootKey = '';
    }

    public function __destruct()
    {
        sodium_memzero($this->rootKey);
        sodium_memzero($this->dhSelfSecret);
        if ($this->chainKeySend !== null) {
            sodium_memzero($this->chainKeySend);
        }
        if ($this->chainKeyRecv !== null) {
            sodium_memzero($this->chainKeyRecv);
        }
        foreach ($this->skippedKeys as &$key) {
            sodium_memzero($key);
        }
    }

    /**
     * Initialize as the initiator (Alice) after a shared secret has been
     * established (e.g., from Noise XX handshake).
     *
     * @param string $sharedSecret 32-byte shared secret from key agreement
     * @param string $remotePublic Bob's initial DH ratchet public key (32 bytes)
     * @param RatchetConfig $config Ratchet configuration
     */
    public static function initInitiator(
        string $sharedSecret,
        string $remotePublic,
        RatchetConfig $config = new RatchetConfig(),
    ): self {
        $ratchet = new self($config);

        // Generate our DH keypair
        $kp = X25519Keypair::generate();
        $ratchet->dhSelfSecret = $kp->secretKeyBytes();
        $ratchet->dhSelfPublic = $kp->publicKeyBytes();
        $ratchet->dhRemote = $remotePublic;

        // Perform initial DH ratchet step
        $dhOutput = sodium_crypto_scalarmult($ratchet->dhSelfSecret, $remotePublic);
        [$ratchet->rootKey, $chainKeySend] = self::kdfRk($sharedSecret, $dhOutput);
        $ratchet->chainKeySend = $chainKeySend;

        return $ratchet;
    }

    /**
     * Initialize as the responder (Bob) after a shared secret has been
     * established.
     *
     * @param string $sharedSecret 32-byte shared secret from key agreement
     * @param X25519Keypair $dhKeypair Bob's initial DH ratchet keypair
     * @param RatchetConfig $config Ratchet configuration
     */
    public static function initResponder(
        string $sharedSecret,
        X25519Keypair $dhKeypair,
        RatchetConfig $config = new RatchetConfig(),
    ): self {
        $ratchet = new self($config);
        $ratchet->dhSelfSecret = $dhKeypair->secretKeyBytes();
        $ratchet->dhSelfPublic = $dhKeypair->publicKeyBytes();
        $ratchet->rootKey = $sharedSecret;

        return $ratchet;
    }

    /**
     * Encrypt a message.
     *
     * @return array{0: RatchetHeader, 1: string} Tuple of (header, ciphertext)
     * @throws CairnException
     */
    public function encrypt(string $plaintext): array
    {
        if ($this->chainKeySend === null) {
            throw new CairnException('no sending chain key established');
        }

        [$newChainKey, $messageKey] = self::kdfCk($this->chainKeySend);
        $this->chainKeySend = $newChainKey;

        $header = new RatchetHeader(
            dhPublic: $this->dhSelfPublic,
            prevChainLen: $this->prevChainLen,
            msgNum: $this->msgNumSend,
        );

        $this->msgNumSend++;

        $nonce = self::deriveNonce($messageKey, $header->msgNum);
        $headerBytes = $header->toJson();

        $ciphertext = Aead::encrypt(
            $this->config->cipher,
            $messageKey,
            $nonce,
            $plaintext,
            $headerBytes,
        );

        return [$header, $ciphertext];
    }

    /**
     * Decrypt a message given the header and ciphertext.
     *
     * @throws CairnException
     */
    public function decrypt(RatchetHeader $header, string $ciphertext): string
    {
        // Try skipped keys first
        $skippedId = bin2hex($header->dhPublic) . ':' . $header->msgNum;
        if (isset($this->skippedKeys[$skippedId])) {
            $mk = $this->skippedKeys[$skippedId];
            unset($this->skippedKeys[$skippedId]);
            return self::decryptWithKey($this->config->cipher, $mk, $header, $ciphertext);
        }

        // Check if peer's DH key changed
        $needDhRatchet = $this->dhRemote === null || $this->dhRemote !== $header->dhPublic;

        if ($needDhRatchet) {
            $this->skipMessageKeys($header->prevChainLen);
            $this->dhRatchet($header->dhPublic);
        }

        $this->skipMessageKeys($header->msgNum);

        if ($this->chainKeyRecv === null) {
            throw new CairnException('no receiving chain key established');
        }

        [$newChainKey, $messageKey] = self::kdfCk($this->chainKeyRecv);
        $this->chainKeyRecv = $newChainKey;
        $this->msgNumRecv++;

        return self::decryptWithKey($this->config->cipher, $messageKey, $header, $ciphertext);
    }

    /**
     * Export the ratchet state for persistence.
     */
    public function exportState(): string
    {
        /** @var array<string, list<int>> $skippedEncoded */
        $skippedEncoded = [];
        foreach ($this->skippedKeys as $id => $key) {
            $skippedEncoded[$id] = array_values(unpack('C*', $key) ?: []);
        }

        return json_encode([
            'dh_self_secret' => array_values(unpack('C*', $this->dhSelfSecret) ?: []),
            'dh_self_public' => array_values(unpack('C*', $this->dhSelfPublic) ?: []),
            'dh_remote' => $this->dhRemote !== null
                ? array_values(unpack('C*', $this->dhRemote) ?: [])
                : null,
            'root_key' => array_values(unpack('C*', $this->rootKey) ?: []),
            'chain_key_send' => $this->chainKeySend !== null
                ? array_values(unpack('C*', $this->chainKeySend) ?: [])
                : null,
            'chain_key_recv' => $this->chainKeyRecv !== null
                ? array_values(unpack('C*', $this->chainKeyRecv) ?: [])
                : null,
            'msg_num_send' => $this->msgNumSend,
            'msg_num_recv' => $this->msgNumRecv,
            'prev_chain_len' => $this->prevChainLen,
            'skipped_keys' => $skippedEncoded,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * Import ratchet state from persisted bytes.
     *
     * @throws CairnException
     */
    public static function importState(string $data, RatchetConfig $config = new RatchetConfig()): self
    {
        try {
            /** @var array<string, mixed> $state */
            $state = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new CairnException('ratchet state deserialization: ' . $e->getMessage(), 0, $e);
        }

        $ratchet = new self($config);

        /** @var list<int> $dhSelfSecret */
        $dhSelfSecret = $state['dh_self_secret'];
        $ratchet->dhSelfSecret = pack('C*', ...$dhSelfSecret);

        /** @var list<int> $dhSelfPublic */
        $dhSelfPublic = $state['dh_self_public'];
        $ratchet->dhSelfPublic = pack('C*', ...$dhSelfPublic);

        if ($state['dh_remote'] !== null) {
            /** @var list<int> $dhRemote */
            $dhRemote = $state['dh_remote'];
            $ratchet->dhRemote = pack('C*', ...$dhRemote);
        }

        /** @var list<int> $rootKey */
        $rootKey = $state['root_key'];
        $ratchet->rootKey = pack('C*', ...$rootKey);

        if ($state['chain_key_send'] !== null) {
            /** @var list<int> $chainKeySend */
            $chainKeySend = $state['chain_key_send'];
            $ratchet->chainKeySend = pack('C*', ...$chainKeySend);
        }

        if ($state['chain_key_recv'] !== null) {
            /** @var list<int> $chainKeyRecv */
            $chainKeyRecv = $state['chain_key_recv'];
            $ratchet->chainKeyRecv = pack('C*', ...$chainKeyRecv);
        }

        /** @var int $msgNumSend */
        $msgNumSend = $state['msg_num_send'];
        $ratchet->msgNumSend = $msgNumSend;

        /** @var int $msgNumRecv */
        $msgNumRecv = $state['msg_num_recv'];
        $ratchet->msgNumRecv = $msgNumRecv;

        /** @var int $prevChainLen */
        $prevChainLen = $state['prev_chain_len'];
        $ratchet->prevChainLen = $prevChainLen;

        if (isset($state['skipped_keys']) && is_array($state['skipped_keys'])) {
            /** @var array<string, list<int>> $skippedKeys */
            $skippedKeys = $state['skipped_keys'];
            foreach ($skippedKeys as $id => $keyBytes) {
                $ratchet->skippedKeys[$id] = pack('C*', ...$keyBytes);
            }
        }

        return $ratchet;
    }

    /**
     * Skip message keys up to (but not including) the given message number.
     *
     * @throws CairnException
     */
    private function skipMessageKeys(int $until): void
    {
        if ($this->chainKeyRecv === null) {
            return;
        }

        $toSkip = max(0, $until - $this->msgNumRecv);
        if ($toSkip > $this->config->maxSkip) {
            throw new CairnException('max skip threshold exceeded');
        }

        $ck = $this->chainKeyRecv;
        for ($i = $this->msgNumRecv; $i < $until; $i++) {
            [$newCk, $mk] = self::kdfCk($ck);
            if ($this->dhRemote === null) {
                throw new CairnException('no remote DH key for skipping');
            }
            $id = bin2hex($this->dhRemote) . ':' . $i;
            $this->skippedKeys[$id] = $mk;
            $ck = $newCk;
            $this->msgNumRecv++;
        }
        $this->chainKeyRecv = $ck;
    }

    /**
     * Perform a DH ratchet step when the peer's public key changes.
     */
    private function dhRatchet(string $newRemotePublic): void
    {
        $this->prevChainLen = $this->msgNumSend;
        $this->msgNumSend = 0;
        $this->msgNumRecv = 0;
        $this->dhRemote = $newRemotePublic;

        // Derive receiving chain key
        $dhOutput = sodium_crypto_scalarmult($this->dhSelfSecret, $newRemotePublic);
        [$this->rootKey, $chainKeyRecv] = self::kdfRk($this->rootKey, $dhOutput);
        $this->chainKeyRecv = $chainKeyRecv;

        // Generate new DH keypair and derive sending chain key
        $newKp = X25519Keypair::generate();
        $this->dhSelfSecret = $newKp->secretKeyBytes();
        $this->dhSelfPublic = $newKp->publicKeyBytes();

        $dhOutput2 = sodium_crypto_scalarmult($this->dhSelfSecret, $newRemotePublic);
        [$this->rootKey, $chainKeySend] = self::kdfRk($this->rootKey, $dhOutput2);
        $this->chainKeySend = $chainKeySend;
    }

    /**
     * Derive new root key and chain key from DH output.
     *
     * @return array{0: string, 1: string} [new_root_key, new_chain_key]
     */
    private static function kdfRk(string $rootKey, string $dhOutput): array
    {
        $output = Kdf::hkdfSha256($dhOutput, Kdf::HKDF_INFO_ROOT_CHAIN, 64, $rootKey);
        return [substr($output, 0, 32), substr($output, 32, 32)];
    }

    /**
     * Derive message key from chain key and advance the chain.
     *
     * @return array{0: string, 1: string} [new_chain_key, message_key]
     */
    private static function kdfCk(string $chainKey): array
    {
        $newCk = Kdf::hkdfSha256($chainKey, Kdf::HKDF_INFO_CHAIN_ADVANCE);
        $mk = Kdf::hkdfSha256($chainKey, Kdf::HKDF_INFO_MSG_ENCRYPT);
        return [$newCk, $mk];
    }

    /**
     * Derive a 12-byte nonce from a message key and message number.
     */
    private static function deriveNonce(string $messageKey, int $msgNum): string
    {
        return substr($messageKey, 0, 8) . pack('N', $msgNum);
    }

    /**
     * Decrypt ciphertext with a specific message key.
     *
     * @throws CairnException
     */
    private static function decryptWithKey(
        CipherSuite $cipher,
        string $messageKey,
        RatchetHeader $header,
        string $ciphertext,
    ): string {
        $nonce = self::deriveNonce($messageKey, $header->msgNum);
        $headerBytes = $header->toJson();
        return Aead::decrypt($cipher, $messageKey, $nonce, $ciphertext, $headerBytes);
    }
}
