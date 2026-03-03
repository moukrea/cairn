/**
 * Custom pairing adapter interface for domain-specific pairing flows.
 *
 * Applications implement this interface for custom transports:
 * NFC tap, Bluetooth LE OOB, email-based verification, hardware token, etc.
 */
export interface PairingMechanismAdapter {
  /** Human-readable name of this mechanism (e.g., "nfc", "bluetooth-le"). */
  name: string;

  /** Create the pairing payload in the application's chosen format/transport. */
  generatePayload(data: Uint8Array): Promise<Uint8Array>;

  /**
   * Parse and validate a received pairing payload from the custom transport.
   * Returns the PAKE credential and optional connection hints.
   */
  consumePayload(data: Uint8Array): Promise<{
    pakeCredential: Uint8Array;
    hints?: string[];
  }>;

  /** Derive the SPAKE2 password bytes from the custom payload data. */
  derivePakeInput(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * Wrapper that bridges a PairingMechanismAdapter into the pairing system.
 */
export class CustomPairingMechanism {
  constructor(private readonly adapter: PairingMechanismAdapter) {}

  get name(): string {
    return this.adapter.name;
  }

  async generatePayload(data: Uint8Array): Promise<Uint8Array> {
    return this.adapter.generatePayload(data);
  }

  async consumePayload(data: Uint8Array): Promise<{
    pakeCredential: Uint8Array;
    hints?: string[];
  }> {
    return this.adapter.consumePayload(data);
  }

  async derivePakeInput(data: Uint8Array): Promise<Uint8Array> {
    return this.adapter.derivePakeInput(data);
  }
}
