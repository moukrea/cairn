<?php

declare(strict_types=1);

namespace Cairn;

/**
 * Channel lifecycle states.
 *
 * Matches packages/rs/cairn-p2p/src/session/channel.rs ChannelState.
 */
enum ChannelState: string
{
    /** ChannelInit sent, waiting for accept/reject from remote peer. */
    case Opening = 'opening';
    /** Accepted and active. */
    case Open = 'open';
    /** Remote peer rejected the channel. */
    case Rejected = 'rejected';
    /** Either side closed the stream. */
    case Closed = 'closed';
}
