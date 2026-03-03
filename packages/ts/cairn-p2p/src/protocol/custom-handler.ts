import { CairnError } from '../errors.js';
import { APP_EXTENSION_START, APP_EXTENSION_END } from './message-types.js';

/** Callback type for custom message handlers. */
export type CustomMessageCallback = (payload: Uint8Array) => void;

/**
 * Registry for application-defined message type handlers (0xF000-0xFFFF).
 */
export class CustomMessageRegistry {
  private handlers = new Map<number, CustomMessageCallback[]>();

  /**
   * Register a handler for a custom message type in the application range.
   *
   * @param typeCode - Message type code (must be in 0xF000-0xFFFF range)
   * @param callback - Handler called when a message of this type is received
   * @throws CairnError if typeCode is outside the application range
   */
  onCustomMessage(typeCode: number, callback: CustomMessageCallback): void {
    if (typeCode < APP_EXTENSION_START || typeCode > APP_EXTENSION_END) {
      throw new CairnError(
        'PROTOCOL',
        `custom message type code 0x${typeCode.toString(16).padStart(4, '0')} ` +
        `is outside the application range (0x${APP_EXTENSION_START.toString(16)}-0x${APP_EXTENSION_END.toString(16)})`,
      );
    }

    const existing = this.handlers.get(typeCode);
    if (existing) {
      existing.push(callback);
    } else {
      this.handlers.set(typeCode, [callback]);
    }
  }

  /**
   * Dispatch a received custom message to registered handlers.
   *
   * @returns true if at least one handler was called
   */
  dispatch(typeCode: number, payload: Uint8Array): boolean {
    const callbacks = this.handlers.get(typeCode);
    if (!callbacks || callbacks.length === 0) {
      return false;
    }
    for (const cb of callbacks) {
      cb(payload);
    }
    return true;
  }
}
