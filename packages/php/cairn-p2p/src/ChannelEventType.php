<?php

declare(strict_types=1);

namespace Cairn;

/**
 * Events emitted by the channel manager.
 */
enum ChannelEventType: string
{
    case Opened = 'opened';
    case Accepted = 'accepted';
    case Rejected = 'rejected';
    case Data = 'data';
    case Closed = 'closed';
}
