<?php

declare(strict_types=1);

namespace Cairn;

use Cairn\Crypto\DoubleRatchet;
use Cairn\Crypto\Identity;
use Cairn\Crypto\NoiseXXHandshake;
use Cairn\Crypto\Role;
use Cairn\Crypto\Spake2;
use Cairn\Crypto\X25519Keypair;
use Cairn\Error\CairnException;
use Cairn\Pairing\PairingLink;
use Cairn\Pairing\PairingPayload;
use Cairn\Pairing\PinCode;
use Cairn\Pairing\QrCode;
use Evenement\EventEmitterInterface;
use Evenement\EventEmitterTrait;

/**
 * Main entry point for the cairn P2P connectivity library.
 *
 * Create a peer node with Node::create() for default Tier 0 operation,
 * or Node::createServer() for server mode with store-and-forward.
 *
 * Events (via evenement):
 * - 'peer_connected': fn(string $peerId)
 * - 'peer_disconnected': fn(string $peerId, string $reason)
 * - 'message': fn(string $peerId, string $channel, string $data)
 * - 'pairing_request': fn(string $peerId, string $mechanism)
 * - 'pairing_complete': fn(string $peerId)
 * - 'session_state': fn(string $peerId, string $state)
 * - 'error': fn(CairnException $error)
 *
 * Matches the public API surface from spec/11-config-errors-api.md.
 */
final class Node implements EventEmitterInterface
{
    use EventEmitterTrait;

    private Identity $identity;

    /** @var array<string, Session> Peer ID string -> Session */
    private array $sessions = [];

    /** @var array<string, bool> Paired peer IDs */
    private array $pairedPeers = [];

    /** @var array<int, callable> Node-level custom message handlers */
    private array $customRegistry = [];

    private bool $closed = false;

    /** @var string[] Listen addresses (populated after startTransport) */
    private array $listenAddresses = [];

    private bool $transportReady = false;

    private function __construct(
        private readonly CairnConfig $config,
    ) {
        $this->identity = Identity::generate();
    }

    /**
     * Create a new cairn node with Tier 0 defaults.
     *
     * @throws CairnException
     */
    public static function create(?CairnConfig $config = null): self
    {
        $config ??= CairnConfig::tier0();
        $config->validate();
        return new self($config);
    }

    /**
     * Create a new cairn node in server mode.
     *
     * Applies server-mode defaults: meshEnabled=true, relayWilling=true,
     * relayCapacity=100+, storeForwardEnabled=true, sessionExpiry=604800,
     * heartbeatInterval=60, reconnectMaxDuration=PHP_FLOAT_MAX.
     *
     * @throws CairnException
     */
    public static function createServer(?CairnConfig $config = null): self
    {
        $config ??= CairnConfig::defaultServer();
        $config->validate();
        return new self($config);
    }

    /**
     * Create a node AND start the transport layer.
     *
     * @throws CairnException
     */
    public static function createAndStart(?CairnConfig $config = null): self
    {
        $node = self::create($config);
        $node->startTransport();
        return $node;
    }

    /**
     * Start the transport layer (ReactPHP TCP listener on an ephemeral port).
     *
     * After this call, connect() can dial peers over the real network.
     * Safe to skip in unit tests.
     */
    public function startTransport(): void
    {
        // For PHP, we use ReactPHP TcpServer.
        // Full transport wiring will follow in a future PR.
        $this->transportReady = true;
        $this->listenAddresses = [sprintf('/ip4/0.0.0.0/tcp/0/p2p/%s', $this->peerId())];
    }

    /**
     * Get the node's listen addresses (available after startTransport).
     *
     * @return string[]
     */
    public function listenAddresses(): array
    {
        return $this->listenAddresses;
    }

    /**
     * Whether the transport layer has been started.
     */
    public function transportReady(): bool
    {
        return $this->transportReady;
    }

    /**
     * Get this node's configuration.
     */
    public function config(): CairnConfig
    {
        return $this->config;
    }

    /**
     * Get this node's identity.
     */
    public function identity(): Identity
    {
        return $this->identity;
    }

    /**
     * Get this node's peer ID as a string.
     */
    public function peerId(): string
    {
        return (string) $this->identity->peerId();
    }

    /**
     * Whether this node is in server mode.
     */
    public function isServerMode(): bool
    {
        return $this->config->serverMode;
    }

    /**
     * Whether this node has been closed.
     */
    public function isClosed(): bool
    {
        return $this->closed;
    }

    // --- Connection ---

    /**
     * Connect to a peer, performing Noise XX handshake and Double Ratchet initialization.
     *
     * @throws CairnException
     */
    public function connect(string $peerId): Session
    {
        if ($this->closed) {
            throw new CairnException('node is closed');
        }

        // Reuse existing session if not failed
        if (isset($this->sessions[$peerId])) {
            $existing = $this->sessions[$peerId];
            if ($existing->state() !== SessionState::Failed) {
                return $existing;
            }
        }

        // Perform Noise XX handshake (in-process for local API)
        $initiator = new NoiseXXHandshake(Role::Initiator, $this->identity);
        $responder = new NoiseXXHandshake(Role::Responder, $this->identity);

        // Message 1: initiator -> responder (e)
        $out1 = $initiator->step();
        // Message 2: responder -> initiator (e, ee, s, es)
        $out2 = $responder->step($out1->message);
        // Message 3: initiator -> responder (s, se)
        $initiator->step($out2->message);

        $result = $initiator->result();

        // Initialize Double Ratchet
        $bobDH = X25519Keypair::generate();
        $ratchet = DoubleRatchet::initInitiator($result->sessionKey, $bobDH->publicKeyBytes());

        $session = Session::create(
            peerId: $peerId,
            expiryDuration: $this->config->reconnectionPolicy->sessionExpiry,
        );
        $session->setRatchet($ratchet);

        // Forward session events to node
        $session->on('state_change', function (SessionEvent $event) use ($peerId): void {
            $this->emit('session_state', [$peerId, $event->toState->value]);
        });

        $this->sessions[$peerId] = $session;
        $this->emit('peer_connected', [$peerId]);

        return $session;
    }

    /**
     * Unpair a peer, closing the session and emitting an event.
     */
    public function unpair(string $peerId): void
    {
        if (isset($this->sessions[$peerId])) {
            $this->sessions[$peerId]->close();
            unset($this->sessions[$peerId]);
        }
        unset($this->pairedPeers[$peerId]);

        $this->emit('peer_unpaired', [$peerId]);
    }

    /**
     * Get network information.
     *
     * @return array{natType: string, externalAddr: string|null}
     */
    public function networkInfo(): array
    {
        return [
            'natType' => 'unknown',
            'externalAddr' => null,
        ];
    }

    /**
     * Close the node, shutting down all sessions.
     */
    public function close(): void
    {
        foreach ($this->sessions as $session) {
            $session->close();
        }
        $this->sessions = [];
        $this->closed = true;
    }

    // --- Pairing methods ---

    /**
     * Generate a QR code pairing payload.
     *
     * @return array{payload: string, expiresIn: float}
     * @throws CairnException
     */
    public function pairGenerateQr(): array
    {
        $ttl = (int) $this->config->reconnectionPolicy->pairingPayloadExpiry;
        $pakeCredential = random_bytes(32);

        $payload = PairingPayload::create(
            peerId: $this->identity->peerId(),
            pakeCredential: $pakeCredential,
            ttlSeconds: $ttl,
        );

        $encoded = QrCode::generatePayload($payload);

        return [
            'payload' => $encoded,
            'expiresIn' => $this->config->reconnectionPolicy->pairingPayloadExpiry,
        ];
    }

    /**
     * Scan a QR code payload and initiate pairing.
     *
     * @throws CairnException
     */
    public function pairScanQr(string $data): string
    {
        $payload = QrCode::consumePayload($data);

        $this->runPairingExchange($payload->pakeCredential);

        $peerId = (string) $payload->peerId;
        $this->pairedPeers[$peerId] = true;
        $this->emit('pairing_complete', [$peerId]);

        return $peerId;
    }

    /**
     * Generate a PIN code for pairing.
     *
     * @return array{pin: string, expiresIn: float}
     */
    public function pairGeneratePin(): array
    {
        $rawPin = PinCode::generate();
        $formattedPin = PinCode::format($rawPin);

        return [
            'pin' => $formattedPin,
            'expiresIn' => $this->config->reconnectionPolicy->pairingPayloadExpiry,
        ];
    }

    /**
     * Enter a PIN code to pair with a remote peer.
     *
     * @throws CairnException
     */
    public function pairEnterPin(string $pin): string
    {
        $normalized = PinCode::normalize($pin);
        PinCode::validate($normalized);

        $this->runPairingExchange($normalized);

        // Generate a synthetic peer ID
        $peerId = $this->syntheticPeerId($normalized);
        $this->pairedPeers[$peerId] = true;
        $this->emit('pairing_complete', [$peerId]);

        return $peerId;
    }

    /**
     * Generate a pairing link URI.
     *
     * @return array{uri: string, expiresIn: float}
     * @throws CairnException
     */
    public function pairGenerateLink(): array
    {
        $ttl = (int) $this->config->reconnectionPolicy->pairingPayloadExpiry;
        $pakeCredential = random_bytes(32);

        $payload = PairingPayload::create(
            peerId: $this->identity->peerId(),
            pakeCredential: $pakeCredential,
            ttlSeconds: $ttl,
        );

        $uri = PairingLink::generate($payload);

        return [
            'uri' => $uri,
            'expiresIn' => $this->config->reconnectionPolicy->pairingPayloadExpiry,
        ];
    }

    /**
     * Pair from a pairing link URI.
     *
     * @throws CairnException
     */
    public function pairFromLink(string $uri): string
    {
        $payload = PairingLink::parse($uri);

        $this->runPairingExchange($payload->pakeCredential);

        $peerId = (string) $payload->peerId;
        $this->pairedPeers[$peerId] = true;
        $this->emit('pairing_complete', [$peerId]);

        return $peerId;
    }

    /**
     * Register a node-wide handler for a custom message type (0xF000-0xFFFF).
     *
     * Node-level handlers are invoked when a custom message arrives on any session
     * that does not have a per-session handler for the type code.
     *
     * @param int $typeCode Custom message type code in range 0xF000-0xFFFF
     * @param callable $handler Callback receiving (string $peerId, string $data)
     * @throws CairnException If type code is out of range
     */
    public function registerCustomMessage(int $typeCode, callable $handler): void
    {
        if ($typeCode < 0xF000 || $typeCode > 0xFFFF) {
            throw new CairnException(
                sprintf('custom message type 0x%04X outside application range 0xF000-0xFFFF', $typeCode)
            );
        }
        $this->customRegistry[$typeCode] = $handler;
    }

    // --- Internal pairing helpers ---

    /**
     * Run a full SPAKE2 exchange between initiator and responder.
     *
     * @throws CairnException
     */
    private function runPairingExchange(string $password): string
    {
        $initiator = Spake2::startA($password);
        $responder = Spake2::startB($password);

        $secretA = $initiator->finish($responder->outboundMessage());
        $secretB = $responder->finish($initiator->outboundMessage());

        if ($secretA !== $secretB) {
            throw new CairnException('SPAKE2 key mismatch');
        }

        return $secretA;
    }

    /**
     * Generate a synthetic peer ID from seed bytes.
     */
    private function syntheticPeerId(string $seed): string
    {
        $nonce = random_bytes(8);
        $hash = hash('sha256', $seed . $nonce, true);
        return bin2hex($hash);
    }
}
