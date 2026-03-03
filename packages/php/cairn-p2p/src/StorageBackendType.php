<?php

declare(strict_types=1);

namespace Cairn;

/**
 * Storage backend for keys, identities, and pairing state.
 */
enum StorageBackendType: string
{
    case Filesystem = 'filesystem';
    case InMemory = 'in_memory';
}
