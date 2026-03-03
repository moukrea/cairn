import { describe, it, expect } from 'vitest';
import {
  CairnError,
  ErrorBehavior,
  TransportExhaustedError,
  SessionExpiredError,
  PeerUnreachableError,
  AuthenticationFailedError,
  PairingRejectedError,
  PairingExpiredError,
  MeshRouteNotFoundError,
  VersionMismatchError,
  DEFAULT_STUN_SERVERS,
  DEFAULT_TRANSPORT_PREFERENCES,
  DEFAULT_RECONNECTION_POLICY,
  DEFAULT_MESH_SETTINGS,
} from 'cairn-p2p';

describe('errors', () => {
  it('CairnError has code and message', () => {
    const err = new CairnError('TEST_CODE', 'test message');
    expect(err.code).toBe('TEST_CODE');
    expect(err.message).toBe('test message');
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('CairnError');
  });

  it('CairnError supports optional details', () => {
    const err = new CairnError('TEST', 'msg', { key: 'value' });
    expect(err.details).toEqual({ key: 'value' });
  });

  const errorClasses = [
    { Cls: TransportExhaustedError, code: 'TRANSPORT_EXHAUSTED', name: 'TransportExhaustedError' },
    { Cls: SessionExpiredError, code: 'SESSION_EXPIRED', name: 'SessionExpiredError' },
    { Cls: PeerUnreachableError, code: 'PEER_UNREACHABLE', name: 'PeerUnreachableError' },
    { Cls: AuthenticationFailedError, code: 'AUTHENTICATION_FAILED', name: 'AuthenticationFailedError' },
    { Cls: PairingRejectedError, code: 'PAIRING_REJECTED', name: 'PairingRejectedError' },
    { Cls: PairingExpiredError, code: 'PAIRING_EXPIRED', name: 'PairingExpiredError' },
    { Cls: MeshRouteNotFoundError, code: 'MESH_ROUTE_NOT_FOUND', name: 'MeshRouteNotFoundError' },
    { Cls: VersionMismatchError, code: 'VERSION_MISMATCH', name: 'VersionMismatchError' },
  ] as const;

  for (const { Cls, code, name } of errorClasses) {
    it(`${name} has code ${code} and extends CairnError`, () => {
      const err = new Cls('test');
      expect(err.code).toBe(code);
      expect(err.name).toBe(name);
      expect(err).toBeInstanceOf(CairnError);
      expect(err).toBeInstanceOf(Error);
    });
  }

  it('all 8 error subclasses exist', () => {
    expect(errorClasses).toHaveLength(8);
  });

  it('ErrorBehavior enum has all 6 values', () => {
    expect(ErrorBehavior.Retry).toBe('retry');
    expect(ErrorBehavior.Reconnect).toBe('reconnect');
    expect(ErrorBehavior.Abort).toBe('abort');
    expect(ErrorBehavior.ReGenerate).toBe('regenerate');
    expect(ErrorBehavior.Wait).toBe('wait');
    expect(ErrorBehavior.Inform).toBe('inform');
  });

  it('CairnError.errorBehavior() returns Abort by default', () => {
    const err = new CairnError('TEST', 'test');
    expect(err.errorBehavior()).toBe(ErrorBehavior.Abort);
  });

  const behaviorMap = [
    { Cls: TransportExhaustedError, behavior: ErrorBehavior.Retry },
    { Cls: SessionExpiredError, behavior: ErrorBehavior.Reconnect },
    { Cls: PeerUnreachableError, behavior: ErrorBehavior.Wait },
    { Cls: AuthenticationFailedError, behavior: ErrorBehavior.Abort },
    { Cls: PairingRejectedError, behavior: ErrorBehavior.Inform },
    { Cls: PairingExpiredError, behavior: ErrorBehavior.ReGenerate },
    { Cls: MeshRouteNotFoundError, behavior: ErrorBehavior.Wait },
    { Cls: VersionMismatchError, behavior: ErrorBehavior.Abort },
  ] as const;

  for (const { Cls, behavior } of behaviorMap) {
    it(`${Cls.name}.errorBehavior() returns ${behavior}`, () => {
      const err = new Cls('test');
      expect(err.errorBehavior()).toBe(behavior);
    });
  }

  it('TransportExhaustedError auto-populates suggestion', () => {
    const err = new TransportExhaustedError('all failed');
    expect(err.details?.suggestion).toContain('signaling server');
  });

  it('MeshRouteNotFoundError auto-populates suggestion', () => {
    const err = new MeshRouteNotFoundError('no route');
    expect(err.details?.suggestion).toContain('direct connection');
  });

  it('VersionMismatchError auto-populates suggestion', () => {
    const err = new VersionMismatchError('mismatch');
    expect(err.details?.suggestion).toContain('update');
  });

  it('custom details override default suggestion', () => {
    const err = new TransportExhaustedError('msg', { suggestion: 'custom' });
    expect(err.details?.suggestion).toBe('custom');
  });
});

describe('config defaults', () => {
  it('DEFAULT_STUN_SERVERS has Google and Cloudflare entries', () => {
    expect(DEFAULT_STUN_SERVERS.length).toBe(3);
    expect(DEFAULT_STUN_SERVERS[0]).toContain('google.com');
    expect(DEFAULT_STUN_SERVERS[2]).toContain('cloudflare.com');
  });

  it('DEFAULT_TRANSPORT_PREFERENCES matches spec order', () => {
    expect(DEFAULT_TRANSPORT_PREFERENCES).toEqual([
      'quic', 'tcp', 'websocket', 'webtransport', 'circuit-relay-v2',
    ]);
  });

  it('DEFAULT_RECONNECTION_POLICY has correct values', () => {
    expect(DEFAULT_RECONNECTION_POLICY.connectTimeout).toBe(30_000);
    expect(DEFAULT_RECONNECTION_POLICY.transportTimeout).toBe(10_000);
    expect(DEFAULT_RECONNECTION_POLICY.reconnectMaxDuration).toBe(3_600_000);
    expect(DEFAULT_RECONNECTION_POLICY.reconnectBackoff.initialDelay).toBe(1_000);
    expect(DEFAULT_RECONNECTION_POLICY.reconnectBackoff.maxDelay).toBe(60_000);
    expect(DEFAULT_RECONNECTION_POLICY.reconnectBackoff.factor).toBe(2.0);
    expect(DEFAULT_RECONNECTION_POLICY.rendezvousPollInterval).toBe(30_000);
    expect(DEFAULT_RECONNECTION_POLICY.sessionExpiry).toBe(86_400_000);
    expect(DEFAULT_RECONNECTION_POLICY.pairingPayloadExpiry).toBe(300_000);
  });

  it('DEFAULT_MESH_SETTINGS has correct values', () => {
    expect(DEFAULT_MESH_SETTINGS.meshEnabled).toBe(false);
    expect(DEFAULT_MESH_SETTINGS.maxHops).toBe(3);
    expect(DEFAULT_MESH_SETTINGS.relayWilling).toBe(false);
    expect(DEFAULT_MESH_SETTINGS.relayCapacity).toBe(10);
  });
});
