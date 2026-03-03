<?php

declare(strict_types=1);

namespace Cairn;

/**
 * Queue overflow strategy (spec section 5).
 */
enum QueueStrategy: string
{
    /** Oldest first; reject new messages when full. */
    case Fifo = 'fifo';
    /** Newest first; discard oldest messages to make room. */
    case Lifo = 'lifo';
}
