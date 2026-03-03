<?php

declare(strict_types=1);

namespace Cairn;

/**
 * Transport protocol in the fallback chain.
 *
 * PHP supports: TCP, WS_TLS, CIRCUIT_RELAY_V2.
 * No QUIC, no WebTransport (no PHP libraries).
 */
enum TransportType: string
{
    case Tcp = 'tcp';
    case WsTls = 'ws_tls';
    case CircuitRelayV2 = 'circuit_relay_v2';
}
