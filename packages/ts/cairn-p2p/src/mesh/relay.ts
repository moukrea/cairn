// Mesh relay forwarding (spec/09 section 9.3)
//
// Handles forwarding opaque encrypted bytes between peers. Relay peers
// cannot read, modify, or forge relayed content.

import { CairnError } from '../errors.js';
import type { MeshConfig } from './index.js';

/** Unique identifier for a relay session. */
export type RelaySessionId = number;

/** A relay session bridging two peers through this node. */
export interface RelaySession {
  /** The unique session identifier. */
  id: RelaySessionId;
  /** The source peer ID (hex, requesting the relay). */
  source: string;
  /** The destination peer ID (hex, being relayed to). */
  destination: string;
}

/**
 * Manages relay sessions for this peer.
 *
 * Enforces relayWilling and relayCapacity from MeshConfig.
 * Each relay session bridges two streams, forwarding opaque bytes.
 */
export class RelayManager {
  private _config: MeshConfig;
  private readonly _sessions = new Map<RelaySessionId, RelaySession>();
  private _nextSessionId = 1;

  constructor(config: MeshConfig) {
    this._config = { ...config };
  }

  /**
   * Request to start a new relay session.
   *
   * Validates that this peer is willing to relay, has capacity,
   * and the destination is not the source.
   */
  requestRelay(source: string, destination: string): RelaySessionId {
    if (!this._config.meshEnabled) {
      throw new CairnError('MESH_DISABLED', 'mesh routing disabled');
    }

    if (!this._config.relayWilling) {
      throw new CairnError('RELAY_NOT_WILLING', 'relay not willing');
    }

    if (this._sessions.size >= this._config.relayCapacity) {
      throw new CairnError(
        'RELAY_CAPACITY_FULL',
        `relay capacity full (${this._sessions.size}/${this._config.relayCapacity})`,
      );
    }

    if (source === destination) {
      throw new CairnError(
        'RELAY_CONNECTION_FAILED',
        'source and destination are the same peer',
      );
    }

    const id = this._nextSessionId++;
    this._sessions.set(id, { id, source, destination });
    return id;
  }

  /** Close a relay session. Returns true if the session existed. */
  closeSession(sessionId: RelaySessionId): boolean {
    return this._sessions.delete(sessionId);
  }

  /** Get the number of active relay sessions. */
  get activeSessionCount(): number {
    return this._sessions.size;
  }

  /** Get a relay session by ID. */
  getSession(sessionId: RelaySessionId): RelaySession | undefined {
    return this._sessions.get(sessionId);
  }

  /** Get the remaining relay capacity. */
  get remainingCapacity(): number {
    return Math.max(0, this._config.relayCapacity - this._sessions.size);
  }

  /** Check whether this peer is willing to relay. */
  get isWilling(): boolean {
    return this._config.relayWilling;
  }

  /** Update the mesh configuration. */
  updateConfig(config: MeshConfig): void {
    this._config = { ...config };
  }
}
