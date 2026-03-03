<?php

declare(strict_types=1);

namespace Cairn;

use Cairn\Crypto\DoubleRatchet;
use Cairn\Error\CairnException;
use Cairn\Protocol\Envelope;
use Cairn\Protocol\MessageType;
use Evenement\EventEmitterInterface;
use Evenement\EventEmitterTrait;
use Ramsey\Uuid\Uuid;

/**
 * Event emitted on every state transition.
 */
final class SessionEvent
{
    public function __construct(
        public readonly string $sessionId,
        public readonly SessionState $fromState,
        public readonly SessionState $toState,
        public readonly float $timestamp,
        public readonly ?string $reason,
    ) {
    }
}

/**
 * Message queue configuration (spec section 5).
 */
final class QueueConfig
{
    public function __construct(
        /** Whether to buffer messages at all. */
        public readonly bool $enabled = true,
        /** Maximum messages to buffer. */
        public readonly int $maxSize = 1000,
        /** Maximum age in seconds before discard. */
        public readonly float $maxAge = 3600.0,
        /** Overflow strategy. */
        public readonly QueueStrategy $strategy = QueueStrategy::Fifo,
    ) {
    }
}

/**
 * A queued message with metadata for age tracking.
 */
final class QueuedMessage
{
    public function __construct(
        public readonly int $sequence,
        public readonly string $payload,
        public readonly float $enqueuedAt,
    ) {
    }
}

/**
 * Message queue for buffering during disconnection.
 *
 * Messages are buffered locally while in Disconnected, Reconnecting, or Suspended states.
 * On session resumption, queued messages are retransmitted in sequence order.
 * On session re-establishment (after expiry), all queued messages are discarded.
 *
 * Matches packages/rs/cairn-p2p/src/session/queue.rs.
 */
final class MessageQueue
{
    /** @var list<QueuedMessage> */
    private array $messages = [];

    public function __construct(
        private readonly QueueConfig $config = new QueueConfig(),
    ) {
    }

    public function enqueue(int $sequence, string $payload): EnqueueResult
    {
        if (!$this->config->enabled) {
            return EnqueueResult::Disabled;
        }

        $this->expireStale();

        $msg = new QueuedMessage(
            sequence: $sequence,
            payload: $payload,
            enqueuedAt: microtime(true),
        );

        if (count($this->messages) >= $this->config->maxSize) {
            return match ($this->config->strategy) {
                QueueStrategy::Fifo => EnqueueResult::Full,
                QueueStrategy::Lifo => $this->evictAndEnqueue($msg),
            };
        }

        $this->messages[] = $msg;
        return EnqueueResult::Enqueued;
    }

    /**
     * Drain all queued messages in sequence order for retransmission.
     *
     * @return list<QueuedMessage>
     */
    public function drain(): array
    {
        $this->expireStale();
        $msgs = $this->messages;
        $this->messages = [];
        return $msgs;
    }

    /**
     * Discard all queued messages.
     */
    public function clear(): void
    {
        $this->messages = [];
    }

    public function len(): int
    {
        return count($this->messages);
    }

    public function isEmpty(): bool
    {
        return count($this->messages) === 0;
    }

    public function remainingCapacity(): int
    {
        return max(0, $this->config->maxSize - count($this->messages));
    }

    public function peek(): ?QueuedMessage
    {
        return $this->messages[0] ?? null;
    }

    public function config(): QueueConfig
    {
        return $this->config;
    }

    private function evictAndEnqueue(QueuedMessage $msg): EnqueueResult
    {
        array_shift($this->messages);
        $this->messages[] = $msg;
        return EnqueueResult::EnqueuedWithEviction;
    }

    private function expireStale(): void
    {
        $now = microtime(true);
        $maxAge = $this->config->maxAge;
        $this->messages = array_values(array_filter(
            $this->messages,
            fn(QueuedMessage $m) => ($now - $m->enqueuedAt) < $maxAge,
        ));
    }
}

/**
 * Heartbeat configuration (spec section 6).
 */
final class HeartbeatConfig
{
    public function __construct(
        /** Interval at which heartbeats are sent (seconds). */
        public readonly float $interval = 30.0,
        /** Time without any data before declaring disconnection (seconds). */
        public readonly float $timeout = 90.0,
    ) {
    }

    public static function aggressive(): self
    {
        return new self(interval: 5.0, timeout: 15.0);
    }

    public static function relaxed(): self
    {
        return new self(interval: 60.0, timeout: 180.0);
    }
}

/**
 * Monitors heartbeat timing and determines connection liveness.
 */
final class HeartbeatMonitor
{
    private float $lastActivity;
    private float $lastHeartbeatSent;

    public function __construct(
        private readonly HeartbeatConfig $config = new HeartbeatConfig(),
    ) {
        $now = microtime(true);
        $this->lastActivity = $now;
        $this->lastHeartbeatSent = $now;
    }

    public function recordActivity(): void
    {
        $this->lastActivity = microtime(true);
    }

    public function recordHeartbeatSent(): void
    {
        $this->lastHeartbeatSent = microtime(true);
    }

    public function isTimedOut(): bool
    {
        return (microtime(true) - $this->lastActivity) >= $this->config->timeout;
    }

    public function shouldSendHeartbeat(): bool
    {
        return (microtime(true) - $this->lastHeartbeatSent) >= $this->config->interval;
    }

    public function timeUntilNextHeartbeat(): float
    {
        $elapsed = microtime(true) - $this->lastHeartbeatSent;
        return max(0.0, $this->config->interval - $elapsed);
    }

    public function timeUntilTimeout(): float
    {
        $elapsed = microtime(true) - $this->lastActivity;
        return max(0.0, $this->config->timeout - $elapsed);
    }

    public function config(): HeartbeatConfig
    {
        return $this->config;
    }

    public function lastActivity(): float
    {
        return $this->lastActivity;
    }
}

/**
 * Session state machine with transition validation and event emission.
 *
 * Enforces the 7-state connection lifecycle from spec/07-reconnection-sessions.md section 2.
 * Matches packages/rs/cairn-p2p/src/session/state_machine.rs.
 */
final class SessionStateMachine implements EventEmitterInterface
{
    use EventEmitterTrait;

    private SessionState $state;

    public function __construct(
        private readonly string $sessionId = '',
        SessionState $initialState = SessionState::Connected,
    ) {
        $this->state = $initialState;
    }

    public function state(): SessionState
    {
        return $this->state;
    }

    public function sessionId(): string
    {
        return $this->sessionId;
    }

    /**
     * Attempt a state transition (alias for transition()).
     *
     * @throws CairnException if the transition is not valid
     */
    public function transitionTo(SessionState $to, ?string $reason = null): void
    {
        $this->transition($to, $reason);
    }

    /**
     * Attempt a state transition.
     *
     * @throws CairnException if the transition is not valid
     */
    public function transition(SessionState $to, ?string $reason = null): void
    {
        if (!self::isValidTransition($this->state, $to)) {
            throw new CairnException(sprintf(
                'invalid session state transition: %s -> %s',
                $this->state->label(),
                $to->label(),
            ));
        }

        $from = $this->state;
        $this->state = $to;

        $event = new SessionEvent(
            sessionId: $this->sessionId,
            fromState: $from,
            toState: $to,
            timestamp: microtime(true),
            reason: $reason,
        );

        $this->emit('state_change', [$event]);
    }

    /**
     * Check whether a transition from one state to another is valid per the spec state diagram.
     *
     * Valid transitions (spec section 2):
     * - Connected -> Unstable (degradation detected)
     * - Connected -> Disconnected (abrupt transport loss)
     * - Unstable -> Disconnected (transport lost)
     * - Unstable -> Connected (recovered)
     * - Disconnected -> Reconnecting (immediate reconnection attempt)
     * - Reconnecting -> Reconnected (transport re-established)
     * - Reconnecting -> Suspended (backoff pause)
     * - Suspended -> Reconnecting (retry after backoff)
     * - Suspended -> Failed (max retries or session expired)
     * - Reconnected -> Connected (session fully restored)
     */
    public static function isValidTransition(SessionState $from, SessionState $to): bool
    {
        return match (true) {
            $from === SessionState::Connected && $to === SessionState::Unstable,
            $from === SessionState::Connected && $to === SessionState::Disconnected,
            $from === SessionState::Unstable && $to === SessionState::Disconnected,
            $from === SessionState::Unstable && $to === SessionState::Connected,
            $from === SessionState::Disconnected && $to === SessionState::Reconnecting,
            $from === SessionState::Reconnecting && $to === SessionState::Reconnected,
            $from === SessionState::Reconnecting && $to === SessionState::Suspended,
            $from === SessionState::Suspended && $to === SessionState::Reconnecting,
            $from === SessionState::Suspended && $to === SessionState::Failed,
            $from === SessionState::Reconnected && $to === SessionState::Connected => true,
            default => false,
        };
    }
}

/**
 * Default session expiry window (24 hours).
 */
const DEFAULT_SESSION_EXPIRY = 86400.0;

/**
 * A session that survives transport disruptions.
 *
 * Holds session identity, state, sequence counters, and expiry information.
 * The session layer is the primary abstraction the application interacts with;
 * transport churn is invisible above this layer.
 *
 * Matches packages/rs/cairn-p2p/src/session/mod.rs Session.
 */
final class Session implements EventEmitterInterface
{
    use EventEmitterTrait;

    public readonly string $id;
    public readonly string $peerId;
    private SessionStateMachine $stateMachine;
    public readonly float $createdAt;
    private float $expiryDuration;
    private int $sequenceTx;
    private int $sequenceRx;
    private int $ratchetEpoch;
    private MessageQueue $queue;
    private HeartbeatMonitor $heartbeat;

    /** E2E encryption via Double Ratchet. */
    private ?DoubleRatchet $ratchet = null;

    /** @var ChannelManager */
    private ChannelManager $channelManager;

    /** @var list<string> Outbound envelopes awaiting transport */
    private array $outbox = [];

    /** @var array<string, list<callable(string): void>> Channel name -> message callbacks */
    private array $messageCallbacks = [];

    /** @var list<callable(SessionState, SessionState): void> State change callbacks */
    private array $stateChangeCallbacks = [];

    /** @var array<int, callable(string): void> Custom message handlers (0xF000-0xFFFF) */
    private array $customHandlers = [];

    private function __construct(
        string $peerId,
        float $expiryDuration,
        QueueConfig $queueConfig,
        HeartbeatConfig $heartbeatConfig,
    ) {
        $this->id = Uuid::uuid7()->toString();
        $this->peerId = $peerId;
        $this->createdAt = microtime(true);
        $this->expiryDuration = $expiryDuration;
        $this->sequenceTx = 0;
        $this->sequenceRx = 0;
        $this->ratchetEpoch = 0;
        $this->queue = new MessageQueue($queueConfig);
        $this->heartbeat = new HeartbeatMonitor($heartbeatConfig);

        $this->channelManager = new ChannelManager();

        $this->stateMachine = new SessionStateMachine($this->id);
        $this->stateMachine->on('state_change', function (SessionEvent $event): void {
            $this->emit('state_change', [$event]);
            foreach ($this->stateChangeCallbacks as $cb) {
                $cb($event->fromState, $event->toState);
            }
        });
    }

    /**
     * Create a new session in the Connected state.
     */
    public static function create(
        string $peerId,
        float $expiryDuration = DEFAULT_SESSION_EXPIRY,
        QueueConfig $queueConfig = new QueueConfig(),
        HeartbeatConfig $heartbeatConfig = new HeartbeatConfig(),
    ): self {
        return new self($peerId, $expiryDuration, $queueConfig, $heartbeatConfig);
    }

    /**
     * Check if the session has expired.
     */
    public function isExpired(): bool
    {
        return (microtime(true) - $this->createdAt) > $this->expiryDuration;
    }

    /**
     * Get the current session state.
     */
    public function state(): SessionState
    {
        return $this->stateMachine->state();
    }

    /**
     * Whether the session is in a connected state (Connected or Unstable).
     */
    public function isConnected(): bool
    {
        return $this->stateMachine->state() === SessionState::Connected
            || $this->stateMachine->state() === SessionState::Unstable;
    }

    /**
     * Attempt a state transition.
     *
     * @throws CairnException
     */
    public function transition(SessionState $to, ?string $reason = null): void
    {
        $this->stateMachine->transition($to, $reason);
    }

    /**
     * Increment and return the next outbound sequence number.
     */
    public function nextSequenceTx(): int
    {
        $seq = $this->sequenceTx;
        $this->sequenceTx++;
        return $seq;
    }

    /**
     * Get the current outbound sequence number.
     */
    public function sequenceTx(): int
    {
        return $this->sequenceTx;
    }

    /**
     * Get the current inbound sequence number.
     */
    public function sequenceRx(): int
    {
        return $this->sequenceRx;
    }

    /**
     * Set the inbound sequence number (used during resumption sync).
     */
    public function setSequenceRx(int $seq): void
    {
        $this->sequenceRx = $seq;
    }

    /**
     * Advance the ratchet epoch (called on reconnection).
     */
    public function advanceRatchetEpoch(): void
    {
        $this->ratchetEpoch++;
    }

    /**
     * Get the ratchet epoch.
     */
    public function ratchetEpoch(): int
    {
        return $this->ratchetEpoch;
    }

    /**
     * Get the expiry duration in seconds.
     */
    public function expiryDuration(): float
    {
        return $this->expiryDuration;
    }

    /**
     * Get the message queue.
     */
    public function queue(): MessageQueue
    {
        return $this->queue;
    }

    /**
     * Get the heartbeat monitor.
     */
    public function heartbeat(): HeartbeatMonitor
    {
        return $this->heartbeat;
    }

    /**
     * Enqueue a message for later delivery (during disconnection).
     */
    public function enqueueMessage(string $payload): EnqueueResult
    {
        $seq = $this->nextSequenceTx();
        return $this->queue->enqueue($seq, $payload);
    }

    /**
     * Drain queued messages for retransmission after resumption.
     *
     * @return list<QueuedMessage>
     */
    public function drainQueue(): array
    {
        return $this->queue->drain();
    }

    // --- Ratchet ---

    /**
     * Set the Double Ratchet for E2E encryption.
     */
    public function setRatchet(DoubleRatchet $ratchet): void
    {
        $this->ratchet = $ratchet;
    }

    /**
     * Get the Double Ratchet, or null if not set.
     */
    public function ratchet(): ?DoubleRatchet
    {
        return $this->ratchet;
    }

    // --- Channels ---

    /**
     * Open a named channel on this session.
     *
     * @throws CairnException
     */
    public function openChannel(string $name, ?string $metadata = null): Channel
    {
        if ($this->state() === SessionState::Failed) {
            throw new CairnException('session is in failed state');
        }

        $channel = $this->channelManager->openChannel($name, $metadata);
        $channel->accept();

        // If we have a ratchet, produce a ChannelInit envelope
        if ($this->ratchet !== null) {
            $this->outbox[] = $this->createChannelInitEnvelope($name);
        }

        return $channel;
    }

    /**
     * Get a channel by stream ID.
     */
    public function getChannel(int $streamId): ?Channel
    {
        return $this->channelManager->getChannel($streamId);
    }

    /**
     * Get the channel manager.
     */
    public function channelManager(): ChannelManager
    {
        return $this->channelManager;
    }

    // --- Send ---

    /**
     * Send data on a channel, encrypting with Double Ratchet and wrapping in an envelope.
     * When disconnected, messages are queued for later retransmission.
     *
     * @throws CairnException
     */
    public function send(Channel $channel, string $data): void
    {
        if (!$channel->isOpen()) {
            throw new CairnException("channel '{$channel->name}' is not open");
        }

        $state = $this->state();
        if ($state === SessionState::Failed) {
            throw new CairnException('session is in failed state');
        }

        // Queue messages when disconnected
        if (in_array($state, [SessionState::Disconnected, SessionState::Reconnecting, SessionState::Suspended], true)) {
            $this->enqueueMessage($data);
            return;
        }

        // Encrypt with Double Ratchet if available
        if ($this->ratchet !== null) {
            [$header, $ciphertext] = $this->ratchet->encrypt($data);
            $headerBytes = $header->toJson();

            // Format: [4-byte header_len BE][header JSON][ciphertext]
            $payload = pack('N', strlen($headerBytes)) . $headerBytes . $ciphertext;
        } else {
            $payload = $data;
        }

        $seq = $this->nextSequenceTx();
        $this->outbox[] = $this->createDataEnvelope($seq, $payload);
    }

    // --- Message callbacks ---

    /**
     * Register a callback for incoming messages on a specific channel.
     *
     * @param callable(string): void $callback
     */
    public function onMessage(Channel $channel, callable $callback): void
    {
        $this->messageCallbacks[$channel->name][] = $callback;
    }

    /**
     * Register a callback for state changes.
     *
     * @param callable(SessionState, SessionState): void $callback
     */
    public function onStateChange(callable $callback): void
    {
        $this->stateChangeCallbacks[] = $callback;
    }

    /**
     * Register a handler for application-defined message types (0xF000-0xFFFF).
     *
     * @param callable(string): void $handler
     * @throws CairnException
     */
    public function onCustomMessage(int $typeCode, callable $handler): void
    {
        if ($typeCode < MessageType::APP_EXTENSION_START || $typeCode > MessageType::APP_EXTENSION_END) {
            throw new CairnException(sprintf(
                'custom message type 0x%04X is outside the application range (0xF000-0xFFFF)',
                $typeCode,
            ));
        }
        $this->customHandlers[$typeCode] = $handler;
    }

    /**
     * Dispatch a custom message to the registered handler.
     */
    public function dispatchCustomMessage(int $typeCode, string $data): bool
    {
        if (!isset($this->customHandlers[$typeCode])) {
            return false;
        }
        ($this->customHandlers[$typeCode])($data);
        return true;
    }

    // --- Incoming dispatch ---

    /**
     * Dispatch an incoming data message to registered callbacks.
     *
     * @param string $channelName Channel name
     * @param string $data Decrypted message data
     */
    public function dispatchMessage(string $channelName, string $data): void
    {
        if (isset($this->messageCallbacks[$channelName])) {
            foreach ($this->messageCallbacks[$channelName] as $cb) {
                $cb($data);
            }
        }
        $this->emit('message', [$this->peerId, $channelName, $data]);
    }

    // --- Outbox ---

    /**
     * Get and clear all pending outbound envelopes.
     *
     * @return list<string>
     */
    public function outbox(): array
    {
        $out = $this->outbox;
        $this->outbox = [];
        return $out;
    }

    // --- Close ---

    /**
     * Close the session and all channels.
     */
    public function close(): void
    {
        $prevState = $this->state();

        // Close all channels
        for ($i = 1; $i <= $this->channelManager->channelCount(); $i++) {
            $ch = $this->channelManager->getChannel($i);
            if ($ch !== null && $ch->state() !== ChannelState::Closed) {
                $ch->close();
            }
        }

        // Transition to Failed if not already
        if ($prevState !== SessionState::Failed) {
            // Force state to Failed by going through valid transitions
            try {
                match ($prevState) {
                    SessionState::Connected => $this->forceToFailed(),
                    SessionState::Unstable => $this->forceToFailed(),
                    SessionState::Disconnected,
                    SessionState::Reconnecting,
                    SessionState::Suspended,
                    SessionState::Reconnected => $this->forceToFailed(),
                    SessionState::Failed => null,
                };
            } catch (CairnException) {
                // Already in an end state, ignore
            }
        }

        // Clean up ratchet key material
        $this->ratchet = null;
    }

    // --- Internal helpers ---

    /**
     * Force the session to the Failed state through valid transitions.
     */
    private function forceToFailed(): void
    {
        $state = $this->state();
        try {
            if ($state === SessionState::Connected || $state === SessionState::Unstable) {
                $this->stateMachine->transition(SessionState::Disconnected);
                $state = SessionState::Disconnected;
            }
            if ($state === SessionState::Disconnected) {
                $this->stateMachine->transition(SessionState::Reconnecting);
                $state = SessionState::Reconnecting;
            }
            if ($state === SessionState::Reconnecting) {
                $this->stateMachine->transition(SessionState::Suspended);
                $state = SessionState::Suspended;
            }
            if ($state === SessionState::Reconnected) {
                $this->stateMachine->transition(SessionState::Connected);
                $state = SessionState::Connected;
                // Recurse to go through Connected -> Failed path
                $this->forceToFailed();
                return;
            }
            if ($state === SessionState::Suspended) {
                $this->stateMachine->transition(SessionState::Failed);
            }
        } catch (CairnException) {
            // Ignore transition errors during forced shutdown
        }
    }

    /**
     * Create a CBOR-encoded data message envelope.
     */
    private function createDataEnvelope(int $seqNum, string $payload): string
    {
        $env = new Envelope(
            version: 1,
            messageType: MessageType::DATA_MESSAGE,
            msgId: Envelope::newMsgId(),
            sessionId: $this->id,
            payload: $payload,
            authTag: pack('J', $seqNum),
        );
        return $env->encode();
    }

    /**
     * Create a CBOR-encoded ChannelInit envelope.
     */
    private function createChannelInitEnvelope(string $channelName): string
    {
        // Minimal CBOR: map(1) { 0: text(channelName) }
        $nameLen = strlen($channelName);
        if ($nameLen < 24) {
            $initPayload = "\xA1\x00" . chr(0x60 + $nameLen) . $channelName;
        } else {
            $initPayload = "\xA1\x00\x78" . chr($nameLen) . $channelName;
        }

        $env = new Envelope(
            version: 1,
            messageType: CHANNEL_INIT_TYPE,
            msgId: Envelope::newMsgId(),
            sessionId: $this->id,
            payload: $initPayload,
            authTag: null,
        );
        return $env->encode();
    }
}
