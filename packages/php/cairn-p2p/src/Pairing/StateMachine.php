<?php

declare(strict_types=1);

namespace Cairn\Pairing;

use Cairn\Crypto\Kdf;
use Cairn\Crypto\PeerId;
use Cairn\Crypto\Spake2;
use Cairn\Crypto\SpakeRole;
use Cairn\Error\CairnException;

/**
 * HKDF info string for pairing session key derivation.
 */
const HKDF_INFO_PAIRING_SESSION = 'cairn-pairing-session-key-v1';

/**
 * HKDF info string for key confirmation derivation.
 */
const HKDF_INFO_KEY_CONFIRM = 'cairn-pairing-key-confirm-v1';

/**
 * Default pairing timeout in seconds.
 */
const DEFAULT_PAIRING_TIMEOUT = 300;

/**
 * Pairing session driving the SPAKE2 exchange and state transitions.
 *
 * Matches the Rust PairingSession in packages/rs/cairn-p2p/src/pairing/state_machine.rs.
 */
final class PairingSession
{
    private PairingState $state;
    private PairingRole $role;
    private PairingFlowType $flowType;
    private ?PeerId $remotePeerId;
    private ?Spake2 $spake2State;
    private ?string $spake2Outbound;
    private ?string $sharedKey;
    private string $localNonce;
    private ?string $remoteNonce;
    private int $createdAt;
    private int $timeout;
    private ?string $failureReason;

    private function __construct(
        PairingRole $role,
        PairingFlowType $flowType,
        int $timeout,
    ) {
        $this->state = PairingState::Idle;
        $this->role = $role;
        $this->flowType = $flowType;
        $this->remotePeerId = null;
        $this->spake2State = null;
        $this->spake2Outbound = null;
        $this->sharedKey = null;
        $this->localNonce = random_bytes(16);
        $this->remoteNonce = null;
        $this->createdAt = time();
        $this->timeout = $timeout;
        $this->failureReason = null;
    }

    /**
     * Create a new initiator session for the initiation flow (SPAKE2).
     *
     * @param PeerId $localPeerId Local peer identity
     * @param string $password PAKE password
     * @param int $timeout Timeout in seconds
     * @return array{0: self, 1: array{type: string, peer_id: PeerId, nonce: string, pake_msg: string|null, flow_type: string}}
     */
    public static function newInitiator(
        PeerId $localPeerId,
        string $password,
        int $timeout = DEFAULT_PAIRING_TIMEOUT,
    ): array {
        $session = new self(PairingRole::Initiator, PairingFlowType::Initiation, $timeout);

        // Start SPAKE2 as side A
        $session->spake2State = Spake2::startA($password);

        $session->state = PairingState::AwaitingPakeExchange;

        $request = [
            'type' => 'pair_request',
            'peer_id' => $localPeerId,
            'nonce' => $session->localNonce,
            'pake_msg' => $session->spake2State->outboundMessage(),
            'flow_type' => PairingFlowType::Initiation->value,
        ];

        return [$session, $request];
    }

    /**
     * Create a new initiator session for the standard flow (no SPAKE2).
     *
     * @param PeerId $localPeerId Local peer identity
     * @param int $timeout Timeout in seconds
     * @return array{0: self, 1: array{type: string, peer_id: PeerId, nonce: string, pake_msg: null, flow_type: string}}
     */
    public static function newStandardInitiator(
        PeerId $localPeerId,
        int $timeout = DEFAULT_PAIRING_TIMEOUT,
    ): array {
        $session = new self(PairingRole::Initiator, PairingFlowType::Standard, $timeout);
        $session->state = PairingState::AwaitingVerification;

        $request = [
            'type' => 'pair_request',
            'peer_id' => $localPeerId,
            'nonce' => $session->localNonce,
            'pake_msg' => null,
            'flow_type' => PairingFlowType::Standard->value,
        ];

        return [$session, $request];
    }

    /**
     * Create a new responder session for the initiation flow (SPAKE2).
     *
     * @param string $password PAKE password (same as initiator)
     * @param int $timeout Timeout in seconds
     */
    public static function newResponder(
        string $password,
        int $timeout = DEFAULT_PAIRING_TIMEOUT,
    ): self {
        $session = new self(PairingRole::Responder, PairingFlowType::Initiation, $timeout);

        $session->spake2State = Spake2::startB($password);
        $session->spake2Outbound = $session->spake2State->outboundMessage();

        return $session;
    }

    /**
     * Create a new responder session for the standard flow (no SPAKE2).
     *
     * @param int $timeout Timeout in seconds
     */
    public static function newStandardResponder(
        int $timeout = DEFAULT_PAIRING_TIMEOUT,
    ): self {
        return new self(PairingRole::Responder, PairingFlowType::Standard, $timeout);
    }

    /**
     * Set a pre-established shared key (from Noise XX handshake, standard flow).
     */
    public function setSharedKey(string $key): void
    {
        $this->sharedKey = $key;
    }

    /**
     * Process a PairRequest message (responder only).
     *
     * @param PeerId $peerPeerId Remote peer's ID
     * @param string $peerNonce Remote peer's nonce
     * @param string|null $pakeMsg Remote peer's SPAKE2 message (null for standard flow)
     * @param PeerId $localPeerId Local peer ID (for challenge response)
     * @return array{type: string, peer_id: PeerId, nonce: string, pake_msg: string}|null Challenge message or null for standard flow
     * @throws CairnException
     */
    public function handleRequest(
        PeerId $peerPeerId,
        string $peerNonce,
        ?string $pakeMsg,
        PeerId $localPeerId,
    ): ?array {
        $this->checkExpired();

        if ($this->role !== PairingRole::Responder) {
            throw new CairnException('only responder can handle PairRequest');
        }

        if ($this->state !== PairingState::Idle) {
            throw new CairnException(sprintf(
                "invalid state transition: expected Idle, got %s",
                $this->state->value,
            ));
        }

        $this->remotePeerId = $peerPeerId;
        $this->remoteNonce = $peerNonce;

        if ($this->flowType === PairingFlowType::Initiation) {
            if ($pakeMsg === null) {
                throw new CairnException('initiation flow requires PAKE message');
            }

            if ($this->spake2State === null) {
                throw new CairnException('SPAKE2 state not initialized');
            }

            // Finish SPAKE2 with initiator's message
            $rawKey = $this->spake2State->finish($pakeMsg);
            $sessionKey = $this->deriveSessionKey($rawKey);
            $this->sharedKey = $sessionKey;
            $this->spake2State = null;

            // Return the stored outbound message as challenge
            $outbound = $this->spake2Outbound;
            if ($outbound === null) {
                throw new CairnException('SPAKE2 outbound message not stored');
            }
            $this->spake2Outbound = null;

            $this->state = PairingState::AwaitingVerification;

            return [
                'type' => 'pair_challenge',
                'peer_id' => $localPeerId,
                'nonce' => $this->localNonce,
                'pake_msg' => $outbound,
            ];
        }

        // Standard flow
        $this->state = PairingState::AwaitingVerification;
        return null;
    }

    /**
     * Process a PairChallenge message (initiator only).
     *
     * @param PeerId $peerPeerId Remote peer's ID
     * @param string $peerNonce Remote peer's nonce
     * @param string $pakeMsg Remote peer's SPAKE2 message
     * @return array{type: string, key_confirmation: string} PairResponse with key confirmation
     * @throws CairnException
     */
    public function handleChallenge(
        PeerId $peerPeerId,
        string $peerNonce,
        string $pakeMsg,
    ): array {
        $this->checkExpired();

        if ($this->role !== PairingRole::Initiator) {
            throw new CairnException('only initiator can handle PairChallenge');
        }

        if ($this->state !== PairingState::AwaitingPakeExchange) {
            throw new CairnException(sprintf(
                "invalid state transition: expected AwaitingPakeExchange, got %s",
                $this->state->value,
            ));
        }

        $this->remotePeerId = $peerPeerId;
        $this->remoteNonce = $peerNonce;

        if ($this->spake2State === null) {
            throw new CairnException('SPAKE2 state already consumed');
        }

        // Finish SPAKE2 with responder's message
        $rawKey = $this->spake2State->finish($pakeMsg);
        $sessionKey = $this->deriveSessionKey($rawKey);
        $this->sharedKey = $sessionKey;
        $this->spake2State = null;

        // Compute and send key confirmation
        $confirmation = $this->computeKeyConfirmation('initiator');
        $this->state = PairingState::AwaitingConfirmation;

        return [
            'type' => 'pair_response',
            'key_confirmation' => $confirmation,
        ];
    }

    /**
     * Process a PairResponse message (responder only, key confirmation from initiator).
     *
     * @param string $keyConfirmation Initiator's key confirmation HMAC
     * @return array{type: string, key_confirmation: string} PairConfirm message
     * @throws CairnException
     */
    public function handleResponse(string $keyConfirmation): array
    {
        $this->checkExpired();

        if ($this->role !== PairingRole::Responder) {
            throw new CairnException('only responder can handle PairResponse');
        }

        if ($this->state !== PairingState::AwaitingVerification) {
            throw new CairnException(sprintf(
                "invalid state transition: expected AwaitingVerification, got %s",
                $this->state->value,
            ));
        }

        // Verify initiator's key confirmation
        $expected = $this->computeKeyConfirmation('initiator');
        if (!hash_equals($expected, $keyConfirmation)) {
            $this->state = PairingState::Failed;
            $this->failureReason = 'PAKE authentication failed';
            throw new CairnException('PAKE authentication failed');
        }

        // Send our own key confirmation
        $confirmation = $this->computeKeyConfirmation('responder');
        $this->state = PairingState::AwaitingConfirmation;

        return [
            'type' => 'pair_confirm',
            'key_confirmation' => $confirmation,
        ];
    }

    /**
     * Process a PairConfirm message.
     *
     * @param string $keyConfirmation Peer's key confirmation HMAC
     * @return array{type: string, key_confirmation: string}|null Optional confirm-back for initiator
     * @throws CairnException
     */
    public function handleConfirm(string $keyConfirmation): ?array
    {
        $this->checkExpired();

        if ($this->state !== PairingState::AwaitingConfirmation) {
            throw new CairnException(sprintf(
                "invalid state transition: expected AwaitingConfirmation, got %s",
                $this->state->value,
            ));
        }

        // Verify the peer's key confirmation
        $label = match ($this->role) {
            PairingRole::Initiator => 'responder',
            PairingRole::Responder => 'initiator',
        };

        $expected = $this->computeKeyConfirmation($label);
        if (!hash_equals($expected, $keyConfirmation)) {
            $this->state = PairingState::Failed;
            $this->failureReason = 'PAKE authentication failed';
            throw new CairnException('PAKE authentication failed');
        }

        $this->state = PairingState::Completed;

        // Initiator sends confirm back
        if ($this->role === PairingRole::Initiator) {
            $ourConfirm = $this->computeKeyConfirmation('initiator');
            return [
                'type' => 'pair_confirm',
                'key_confirmation' => $ourConfirm,
            ];
        }

        return null;
    }

    /**
     * Handle a PairReject message.
     *
     * @throws CairnException Always throws to signal rejection
     */
    public function handleReject(PairRejectReason $reason): never
    {
        $this->state = PairingState::Failed;
        $this->failureReason = 'rejected by peer: ' . $reason->value;
        throw new CairnException('pairing rejected: ' . $reason->value);
    }

    /**
     * After SAS verification (standard flow), send key confirmation.
     *
     * @return array{type: string, key_confirmation: string}
     * @throws CairnException
     */
    public function sendKeyConfirmation(): array
    {
        if ($this->state !== PairingState::AwaitingVerification) {
            throw new CairnException(sprintf(
                "invalid state transition: expected AwaitingVerification, got %s",
                $this->state->value,
            ));
        }

        $label = match ($this->role) {
            PairingRole::Initiator => 'initiator',
            PairingRole::Responder => 'responder',
        };

        $confirmation = $this->computeKeyConfirmation($label);
        $this->state = PairingState::AwaitingConfirmation;

        $type = match ($this->role) {
            PairingRole::Initiator => 'pair_response',
            PairingRole::Responder => 'pair_confirm',
        };

        return [
            'type' => $type,
            'key_confirmation' => $confirmation,
        ];
    }

    /**
     * Check if this session has expired.
     */
    public function isExpired(): bool
    {
        return (time() - $this->createdAt) > $this->timeout;
    }

    /**
     * Get the shared key (only available in Completed state).
     */
    public function sharedKey(): ?string
    {
        if ($this->state !== PairingState::Completed) {
            return null;
        }
        return $this->sharedKey;
    }

    /**
     * Get the current state.
     */
    public function state(): PairingState
    {
        return $this->state;
    }

    /**
     * Get the remote peer ID (if known).
     */
    public function remotePeerId(): ?PeerId
    {
        return $this->remotePeerId;
    }

    /**
     * Get the flow type.
     */
    public function flowType(): PairingFlowType
    {
        return $this->flowType;
    }

    /**
     * Get the role.
     */
    public function role(): PairingRole
    {
        return $this->role;
    }

    /**
     * Get the local nonce.
     */
    public function localNonce(): string
    {
        return $this->localNonce;
    }

    /**
     * Set the remote nonce (for testing/standard flow).
     */
    public function setRemoteNonce(string $nonce): void
    {
        $this->remoteNonce = $nonce;
    }

    /**
     * Get the failure reason (if in Failed state).
     */
    public function failureReason(): ?string
    {
        return $this->failureReason;
    }

    /**
     * Derive session key from SPAKE2 raw key via HKDF.
     */
    private function deriveSessionKey(string $rawKey): string
    {
        // salt = initiator_nonce || responder_nonce
        $salt = '';
        if ($this->role === PairingRole::Initiator) {
            $salt .= $this->localNonce;
            if ($this->remoteNonce !== null) {
                $salt .= $this->remoteNonce;
            }
        } else {
            if ($this->remoteNonce !== null) {
                $salt .= $this->remoteNonce;
            }
            $salt .= $this->localNonce;
        }

        return Kdf::hkdfSha256($rawKey, HKDF_INFO_PAIRING_SESSION, 32, $salt);
    }

    /**
     * Compute HMAC-SHA256 key confirmation for the given label.
     *
     * @throws CairnException
     */
    private function computeKeyConfirmation(string $label): string
    {
        if ($this->sharedKey === null) {
            throw new CairnException('no shared key for key confirmation');
        }

        // Derive a confirmation key via HKDF
        $confirmKey = Kdf::hkdfSha256($this->sharedKey, HKDF_INFO_KEY_CONFIRM);

        // HMAC-SHA256(confirm_key, label)
        return hash_hmac('sha256', $label, $confirmKey, true);
    }

    /**
     * Check if expired and throw if so.
     *
     * @throws CairnException
     */
    private function checkExpired(): void
    {
        if ($this->isExpired()) {
            $this->state = PairingState::Failed;
            $this->failureReason = 'pairing timed out';
            throw new CairnException(sprintf('pairing timed out after %d seconds', $this->timeout));
        }
    }
}
