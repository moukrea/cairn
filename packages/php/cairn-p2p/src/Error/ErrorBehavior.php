<?php

declare(strict_types=1);

namespace Cairn\Error;

/**
 * Recommended recovery action for a given error.
 *
 * Matches packages/rs/cairn-p2p/src/error.rs ErrorBehavior.
 */
enum ErrorBehavior: string
{
    /** Retry with different transport configuration. */
    case Retry = 'retry';

    /** Re-establish the session (no re-pairing needed). */
    case Reconnect = 'reconnect';

    /** Stop -- manual intervention required. */
    case Abort = 'abort';

    /** Generate a new pairing payload. */
    case ReGenerate = 'regenerate';

    /** Background poll / wait for availability. */
    case Wait = 'wait';

    /** Inform the user -- no automatic recovery. */
    case Inform = 'inform';
}
