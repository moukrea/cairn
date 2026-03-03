/**
 * Recommended recovery action for a given error.
 */
export enum ErrorBehavior {
  Retry = 'retry',
  Reconnect = 'reconnect',
  Abort = 'abort',
  ReGenerate = 'regenerate',
  Wait = 'wait',
  Inform = 'inform',
}

/**
 * Base error class for all cairn errors.
 *
 * Every error carries a machine-readable `code` and optional structured
 * `details` for diagnostic context.
 */
export class CairnError extends Error {
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'CairnError';
    this.code = code;
    this.details = details;
  }

  errorBehavior(): ErrorBehavior {
    return ErrorBehavior.Abort;
  }
}

/**
 * All transports in the fallback chain failed.
 *
 * Details include per-transport failures and suggestions (e.g., deploy a
 * signaling server and/or TURN relay).
 */
export class TransportExhaustedError extends CairnError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('TRANSPORT_EXHAUSTED', message, {
      suggestion: 'deploy the cairn signaling server and/or TURN relay',
      ...details,
    });
    this.name = 'TransportExhaustedError';
  }

  errorBehavior(): ErrorBehavior {
    return ErrorBehavior.Retry;
  }
}

/**
 * Session exceeded the expiry window.
 *
 * Re-establishment via Noise XX handshake is needed; no re-pairing required.
 */
export class SessionExpiredError extends CairnError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('SESSION_EXPIRED', message, details);
    this.name = 'SessionExpiredError';
  }

  errorBehavior(): ErrorBehavior {
    return ErrorBehavior.Reconnect;
  }
}

/**
 * Peer not found at any rendezvous point within timeout.
 */
export class PeerUnreachableError extends CairnError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('PEER_UNREACHABLE', message, details);
    this.name = 'PeerUnreachableError';
  }

  errorBehavior(): ErrorBehavior {
    return ErrorBehavior.Wait;
  }
}

/**
 * Session resumption crypto verification failed.
 *
 * Possible key compromise — reject connection and alert application.
 */
export class AuthenticationFailedError extends CairnError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('AUTHENTICATION_FAILED', message, details);
    this.name = 'AuthenticationFailedError';
  }

  errorBehavior(): ErrorBehavior {
    return ErrorBehavior.Abort;
  }
}

/**
 * Remote peer rejected pairing request.
 */
export class PairingRejectedError extends CairnError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('PAIRING_REJECTED', message, details);
    this.name = 'PairingRejectedError';
  }

  errorBehavior(): ErrorBehavior {
    return ErrorBehavior.Inform;
  }
}

/**
 * Pairing payload (pin, QR, link) has expired.
 *
 * Generate a new payload to retry.
 */
export class PairingExpiredError extends CairnError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('PAIRING_EXPIRED', message, details);
    this.name = 'PairingExpiredError';
  }

  errorBehavior(): ErrorBehavior {
    return ErrorBehavior.ReGenerate;
  }
}

/**
 * No route to destination through mesh network.
 */
export class MeshRouteNotFoundError extends CairnError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('MESH_ROUTE_NOT_FOUND', message, {
      suggestion: 'try a direct connection or wait for mesh route discovery',
      ...details,
    });
    this.name = 'MeshRouteNotFoundError';
  }

  errorBehavior(): ErrorBehavior {
    return ErrorBehavior.Wait;
  }
}

/**
 * No common protocol version between peers.
 *
 * Details include the peer's supported version range so the application
 * can inform the user which peer needs updating.
 */
export class VersionMismatchError extends CairnError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('VERSION_MISMATCH', message, {
      suggestion: 'peer needs to update to a compatible cairn version',
      ...details,
    });
    this.name = 'VersionMismatchError';
  }

  errorBehavior(): ErrorBehavior {
    return ErrorBehavior.Abort;
  }
}
