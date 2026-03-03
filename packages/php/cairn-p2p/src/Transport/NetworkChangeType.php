<?php

declare(strict_types=1);

namespace Cairn\Transport;

/**
 * Network change events detected by OS-level monitoring (spec section 7).
 *
 * Matches packages/rs/cairn-p2p/src/session/reconnection.rs NetworkChange.
 */
enum NetworkChangeType: string
{
    case InterfaceUp = 'interface_up';
    case InterfaceDown = 'interface_down';
    case AddressChanged = 'address_changed';
}
