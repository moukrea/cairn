import { CairnError } from '../errors.js';

// ---------------------------------------------------------------------------
// Connection states (spec/07 section 2)
// ---------------------------------------------------------------------------

/** Connection lifecycle states per spec section 2. */
export type ConnectionState =
  | 'connected'
  | 'unstable'
  | 'disconnected'
  | 'reconnecting'
  | 'suspended'
  | 'reconnected'
  | 'failed';

// ---------------------------------------------------------------------------
// State transition validation
// ---------------------------------------------------------------------------

/** Valid transitions per the spec state diagram. */
const VALID_TRANSITIONS: ReadonlyArray<[ConnectionState, ConnectionState]> = [
  ['connected', 'unstable'],
  ['connected', 'disconnected'],
  ['unstable', 'disconnected'],
  ['unstable', 'connected'],
  ['disconnected', 'reconnecting'],
  ['reconnecting', 'reconnected'],
  ['reconnecting', 'suspended'],
  ['suspended', 'reconnecting'],
  ['suspended', 'failed'],
  ['reconnected', 'connected'],
];

/** Check whether a transition from `from` to `to` is valid. */
export function isValidTransition(from: ConnectionState, to: ConnectionState): boolean {
  return VALID_TRANSITIONS.some(([f, t]) => f === from && t === to);
}

// ---------------------------------------------------------------------------
// Session events
// ---------------------------------------------------------------------------

/** Event emitted on every state transition. */
export interface StateChangedEvent {
  sessionId: string;
  fromState: ConnectionState;
  toState: ConnectionState;
  timestamp: number;
  reason?: string;
}

export type StateChangedListener = (event: StateChangedEvent) => void;

export interface SessionStateMachineEvents {
  state_changed: (event: StateChangedEvent) => void;
}

// ---------------------------------------------------------------------------
// SessionStateMachine
// ---------------------------------------------------------------------------

/**
 * Validates and executes session state transitions, emitting events on each transition.
 *
 * Enforces the 7-state connection lifecycle from spec/07-reconnection-sessions.md section 2.
 */
export class SessionStateMachine {
  private readonly _sessionId: string;
  private _state: ConnectionState;
  private readonly _listeners: StateChangedListener[] = [];

  constructor(sessionId: string, initialState: ConnectionState = 'connected') {
    this._sessionId = sessionId;
    this._state = initialState;
  }

  /** Get the current state. */
  get state(): ConnectionState {
    return this._state;
  }

  /** Get the session ID. */
  get sessionId(): string {
    return this._sessionId;
  }

  /** Subscribe to state change events. */
  onStateChanged(listener: StateChangedListener): void {
    this._listeners.push(listener);
  }

  /**
   * Attempt a state transition.
   *
   * Throws CairnError if the transition is not allowed by the state diagram.
   * Calls all registered state_changed listeners on success.
   */
  transition(to: ConnectionState, reason?: string): void {
    if (!isValidTransition(this._state, to)) {
      throw new CairnError(
        'PROTOCOL',
        `invalid session state transition: ${this._state} -> ${to}`,
      );
    }

    const from = this._state;
    this._state = to;

    const event: StateChangedEvent = {
      sessionId: this._sessionId,
      fromState: from,
      toState: to,
      timestamp: Date.now(),
      reason,
    };

    for (const listener of this._listeners) {
      listener(event);
    }
  }
}
