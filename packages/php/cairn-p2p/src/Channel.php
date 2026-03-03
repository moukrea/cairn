<?php

declare(strict_types=1);

namespace Cairn;

use Cairn\Error\CairnException;
use Evenement\EventEmitterInterface;
use Evenement\EventEmitterTrait;
use Ramsey\Uuid\Uuid;

/**
 * Prefix for reserved cairn-internal channel names.
 */
const RESERVED_CHANNEL_PREFIX = '__cairn_';

/**
 * Reserved channel name for store-and-forward operations.
 */
const CHANNEL_FORWARD = '__cairn_forward';

/**
 * Message type code for ChannelInit (first message on a new stream).
 */
const CHANNEL_INIT_TYPE = 0x0303;

/**
 * Validate that a channel name is not reserved.
 *
 * Application code cannot open channels with the `__cairn_` prefix.
 *
 * @throws CairnException
 */
function validateChannelName(string $name): void
{
    if ($name === '') {
        throw new CairnException('channel name must not be empty');
    }
    if (str_starts_with($name, RESERVED_CHANNEL_PREFIX)) {
        throw new CairnException(sprintf(
            "channel name '%s' uses reserved prefix '%s'",
            $name,
            RESERVED_CHANNEL_PREFIX,
        ));
    }
}

/**
 * A named channel multiplexed over a stream.
 *
 * PHP does not use yamux -- channels are multiplexed via framed messages
 * with stream IDs. Each Channel maps 1:1 to a logical stream ID.
 *
 * Matches packages/rs/cairn-p2p/src/session/channel.rs Channel.
 */
final class Channel
{
    private ChannelState $state;

    public function __construct(
        public readonly string $name,
        public readonly int $streamId,
        public readonly ?string $metadata = null,
    ) {
        $this->state = ChannelState::Opening;
    }

    public function state(): ChannelState
    {
        return $this->state;
    }

    /**
     * Transition to the Open state (accepted by remote).
     *
     * @throws CairnException
     */
    public function accept(): void
    {
        if ($this->state !== ChannelState::Opening) {
            throw new CairnException(sprintf(
                "cannot accept channel '%s' in state %s",
                $this->name,
                $this->state->value,
            ));
        }
        $this->state = ChannelState::Open;
    }

    /**
     * Transition to the Rejected state.
     *
     * @throws CairnException
     */
    public function reject(): void
    {
        if ($this->state !== ChannelState::Opening) {
            throw new CairnException(sprintf(
                "cannot reject channel '%s' in state %s",
                $this->name,
                $this->state->value,
            ));
        }
        $this->state = ChannelState::Rejected;
    }

    /**
     * Transition to the Closed state.
     *
     * @throws CairnException
     */
    public function close(): void
    {
        if ($this->state === ChannelState::Closed) {
            throw new CairnException(sprintf(
                "channel '%s' is already closed",
                $this->name,
            ));
        }
        $this->state = ChannelState::Closed;
    }

    /**
     * Check if the channel is open and ready for data flow.
     */
    public function isOpen(): bool
    {
        return $this->state === ChannelState::Open;
    }
}

/**
 * Application data payload with reliable delivery semantics (0x0300).
 */
final class DataMessage
{
    public function __construct(
        /** Unique message identifier (UUID v7, 16 bytes). */
        public readonly string $msgId,
        /** Application data payload. */
        public readonly string $payload,
    ) {
    }

    public static function create(string $payload): self
    {
        return new self(
            msgId: Uuid::uuid7()->getBytes(),
            payload: $payload,
        );
    }
}

/**
 * Acknowledges successful receipt of a DataMessage (0x0301).
 */
final class DataAck
{
    public function __construct(
        public readonly string $ackedMsgId,
    ) {
    }
}

/**
 * Negative acknowledgment, requesting retransmission (0x0302).
 */
final class DataNack
{
    public function __construct(
        public readonly string $nackedMsgId,
        public readonly ?string $reason = null,
    ) {
    }
}

/**
 * Manages channels within a session.
 *
 * Tracks open channels by stream ID and emits events for channel lifecycle changes.
 * Matches packages/rs/cairn-p2p/src/session/channel.rs ChannelManager.
 */
final class ChannelManager implements EventEmitterInterface
{
    use EventEmitterTrait;

    /** @var array<int, Channel> */
    private array $channels = [];
    private int $nextStreamId = 1;

    /**
     * Open a new channel on a given stream.
     *
     * Validates the channel name, creates the channel in Opening state.
     *
     * @throws CairnException
     */
    public function openChannel(string $name, ?string $metadata = null): Channel
    {
        validateChannelName($name);

        $streamId = $this->nextStreamId++;
        $channel = new Channel($name, $streamId, $metadata);
        $this->channels[$streamId] = $channel;

        $this->emit('channel_opened', [$channel]);

        return $channel;
    }

    /**
     * Handle an incoming ChannelInit from a remote peer.
     *
     * Creates the channel and emits an Opened event. The application should
     * call acceptChannel() or rejectChannel() in response.
     *
     * @throws CairnException
     */
    public function handleChannelInit(int $streamId, string $channelName, ?string $metadata = null): Channel
    {
        if (isset($this->channels[$streamId])) {
            throw new CairnException(sprintf('stream %d already has a channel', $streamId));
        }

        $channel = new Channel($channelName, $streamId, $metadata);
        $this->channels[$streamId] = $channel;

        $this->emit('channel_opened', [$channel]);

        return $channel;
    }

    /**
     * Accept an incoming channel.
     *
     * @throws CairnException
     */
    public function acceptChannel(int $streamId): void
    {
        $channel = $this->getChannelOrThrow($streamId);
        $channel->accept();
        $this->emit('channel_accepted', [$channel]);
    }

    /**
     * Reject an incoming channel.
     *
     * @throws CairnException
     */
    public function rejectChannel(int $streamId, ?string $reason = null): void
    {
        $channel = $this->getChannelOrThrow($streamId);
        $channel->reject();
        $this->emit('channel_rejected', [$channel, $reason]);
    }

    /**
     * Handle incoming data on a channel.
     *
     * @throws CairnException
     */
    public function handleData(int $streamId, DataMessage $message): void
    {
        $channel = $this->getChannelOrThrow($streamId);

        if (!$channel->isOpen()) {
            throw new CairnException(sprintf(
                "channel '%s' is not open (state: %s)",
                $channel->name,
                $channel->state()->value,
            ));
        }

        $this->emit('channel_data', [$channel, $message]);
    }

    /**
     * Close a channel.
     *
     * @throws CairnException
     */
    public function closeChannel(int $streamId): void
    {
        $channel = $this->getChannelOrThrow($streamId);
        $channel->close();
        $this->emit('channel_closed', [$channel]);
    }

    /**
     * Get a channel by stream ID.
     */
    public function getChannel(int $streamId): ?Channel
    {
        return $this->channels[$streamId] ?? null;
    }

    /**
     * Get the number of tracked channels.
     */
    public function channelCount(): int
    {
        return count($this->channels);
    }

    /**
     * @throws CairnException
     */
    private function getChannelOrThrow(int $streamId): Channel
    {
        return $this->channels[$streamId]
            ?? throw new CairnException(sprintf('no channel on stream %d', $streamId));
    }
}
