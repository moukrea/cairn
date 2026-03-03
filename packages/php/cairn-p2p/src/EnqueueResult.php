<?php

declare(strict_types=1);

namespace Cairn;

/**
 * Enqueue result.
 */
enum EnqueueResult: string
{
    case Enqueued = 'enqueued';
    case Disabled = 'disabled';
    case Full = 'full';
    case EnqueuedWithEviction = 'enqueued_with_eviction';
}
