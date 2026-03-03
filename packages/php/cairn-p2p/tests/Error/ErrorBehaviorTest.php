<?php

declare(strict_types=1);

namespace Cairn\Tests\Error;

use Cairn\Error\AuthenticationFailed;
use Cairn\Error\CairnException;
use Cairn\Error\ErrorBehavior;
use Cairn\Error\MeshRouteNotFound;
use Cairn\Error\PairingExpired;
use Cairn\Error\PairingRejected;
use Cairn\Error\PeerUnreachable;
use Cairn\Error\SessionExpired;
use Cairn\Error\TransportExhausted;
use Cairn\Error\VersionMismatch;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ErrorBehavior::class)]
#[CoversClass(CairnException::class)]
#[CoversClass(TransportExhausted::class)]
#[CoversClass(SessionExpired::class)]
#[CoversClass(PeerUnreachable::class)]
#[CoversClass(AuthenticationFailed::class)]
#[CoversClass(PairingRejected::class)]
#[CoversClass(PairingExpired::class)]
#[CoversClass(MeshRouteNotFound::class)]
#[CoversClass(VersionMismatch::class)]
final class ErrorBehaviorTest extends TestCase
{
    // --- ErrorBehavior enum ---

    public function testErrorBehaviorValues(): void
    {
        $this->assertSame('retry', ErrorBehavior::Retry->value);
        $this->assertSame('reconnect', ErrorBehavior::Reconnect->value);
        $this->assertSame('abort', ErrorBehavior::Abort->value);
        $this->assertSame('regenerate', ErrorBehavior::ReGenerate->value);
        $this->assertSame('wait', ErrorBehavior::Wait->value);
        $this->assertSame('inform', ErrorBehavior::Inform->value);
    }

    // --- Base CairnException ---

    public function testBaseCairnExceptionDefaultsToAbort(): void
    {
        $e = new CairnException('generic error');
        $this->assertSame(ErrorBehavior::Abort, $e->behavior());
        $this->assertSame('generic error', $e->getMessage());
    }

    public function testCairnExceptionIsRuntimeException(): void
    {
        $e = new CairnException('test');
        $this->assertInstanceOf(\RuntimeException::class, $e);
    }

    // --- TransportExhausted ---

    public function testTransportExhaustedBehavior(): void
    {
        $e = new TransportExhausted('QUIC: timeout, TCP: refused', 'deploy a TURN relay');
        $this->assertSame(ErrorBehavior::Retry, $e->behavior());
    }

    public function testTransportExhaustedMessage(): void
    {
        $e = new TransportExhausted('TCP: refused', 'check firewall');
        $this->assertStringContainsString('all transports exhausted', $e->getMessage());
        $this->assertStringContainsString('TCP: refused', $e->getMessage());
        $this->assertStringContainsString('check firewall', $e->getMessage());
    }

    public function testTransportExhaustedFields(): void
    {
        $e = new TransportExhausted('details', 'suggestion');
        $this->assertSame('details', $e->details);
        $this->assertSame('suggestion', $e->suggestion);
    }

    // --- SessionExpired ---

    public function testSessionExpiredBehavior(): void
    {
        $e = new SessionExpired('sess-123', 86400.0);
        $this->assertSame(ErrorBehavior::Reconnect, $e->behavior());
    }

    public function testSessionExpiredMessage(): void
    {
        $e = new SessionExpired('sess-123', 86400.0);
        $this->assertStringContainsString('session expired after', $e->getMessage());
        $this->assertStringContainsString('86400', $e->getMessage());
    }

    public function testSessionExpiredFields(): void
    {
        $e = new SessionExpired('sess-abc', 3600.0);
        $this->assertSame('sess-abc', $e->sessionId);
        $this->assertSame(3600.0, $e->expiryDuration);
    }

    // --- PeerUnreachable ---

    public function testPeerUnreachableBehavior(): void
    {
        $e = new PeerUnreachable('peer-abc', 30.0);
        $this->assertSame(ErrorBehavior::Wait, $e->behavior());
    }

    public function testPeerUnreachableMessage(): void
    {
        $e = new PeerUnreachable('peer-abc', 30.0);
        $this->assertStringContainsString('peer-abc', $e->getMessage());
        $this->assertStringContainsString('unreachable', $e->getMessage());
    }

    // --- AuthenticationFailed ---

    public function testAuthenticationFailedBehavior(): void
    {
        $e = new AuthenticationFailed('sess-456');
        $this->assertSame(ErrorBehavior::Abort, $e->behavior());
    }

    public function testAuthenticationFailedMessage(): void
    {
        $e = new AuthenticationFailed('sess-456');
        $this->assertStringContainsString('authentication failed', $e->getMessage());
        $this->assertStringContainsString('sess-456', $e->getMessage());
        $this->assertStringContainsString('key compromise', $e->getMessage());
    }

    // --- PairingRejected ---

    public function testPairingRejectedBehavior(): void
    {
        $e = new PairingRejected('peer-xyz');
        $this->assertSame(ErrorBehavior::Inform, $e->behavior());
    }

    public function testPairingRejectedMessage(): void
    {
        $e = new PairingRejected('peer-xyz');
        $this->assertStringContainsString('pairing rejected', $e->getMessage());
        $this->assertStringContainsString('peer-xyz', $e->getMessage());
    }

    // --- PairingExpired ---

    public function testPairingExpiredBehavior(): void
    {
        $e = new PairingExpired(300.0);
        $this->assertSame(ErrorBehavior::ReGenerate, $e->behavior());
    }

    public function testPairingExpiredMessage(): void
    {
        $e = new PairingExpired(300.0);
        $this->assertStringContainsString('pairing payload expired', $e->getMessage());
        $this->assertStringContainsString('300', $e->getMessage());
        $this->assertStringContainsString('Generate a new payload', $e->getMessage());
    }

    // --- MeshRouteNotFound ---

    public function testMeshRouteNotFoundBehavior(): void
    {
        $e = new MeshRouteNotFound('peer-mesh', 'try direct connection');
        $this->assertSame(ErrorBehavior::Wait, $e->behavior());
    }

    public function testMeshRouteNotFoundMessage(): void
    {
        $e = new MeshRouteNotFound('peer-mesh', 'try direct');
        $this->assertStringContainsString('no mesh route found', $e->getMessage());
        $this->assertStringContainsString('peer-mesh', $e->getMessage());
        $this->assertStringContainsString('try direct', $e->getMessage());
    }

    // --- VersionMismatch ---

    public function testVersionMismatchBehavior(): void
    {
        $e = new VersionMismatch('1.0', '2.0', 'update needed');
        $this->assertSame(ErrorBehavior::Abort, $e->behavior());
    }

    public function testVersionMismatchMessage(): void
    {
        $e = new VersionMismatch('1.0', '2.0', 'peer needs to update');
        $this->assertStringContainsString('protocol version mismatch', $e->getMessage());
        $this->assertStringContainsString('local 1.0', $e->getMessage());
        $this->assertStringContainsString('remote 2.0', $e->getMessage());
        $this->assertStringContainsString('peer needs to update', $e->getMessage());
    }

    public function testVersionMismatchFields(): void
    {
        $e = new VersionMismatch('1.0', '2.0', 'update');
        $this->assertSame('1.0', $e->localVersion);
        $this->assertSame('2.0', $e->remoteVersion);
        $this->assertSame('update', $e->suggestion);
    }

    // --- Default suggestion auto-fill ---

    public function testTransportExhaustedDefaultSuggestion(): void
    {
        $e = new TransportExhausted('QUIC: timeout');
        $this->assertSame('deploy the cairn signaling server and/or TURN relay', $e->suggestion);
        $this->assertSame('deploy the cairn signaling server and/or TURN relay', $e->suggestion());
        $this->assertStringContainsString('deploy the cairn signaling server', $e->getMessage());
    }

    public function testMeshRouteNotFoundDefaultSuggestion(): void
    {
        $e = new MeshRouteNotFound('peer-mesh');
        $this->assertSame('try a direct connection or wait for mesh route discovery', $e->suggestion);
        $this->assertSame('try a direct connection or wait for mesh route discovery', $e->suggestion());
        $this->assertStringContainsString('try a direct connection', $e->getMessage());
    }

    public function testVersionMismatchDefaultSuggestion(): void
    {
        $e = new VersionMismatch('1.0', '2.0');
        $this->assertSame('peer needs to update to a compatible cairn version', $e->suggestion);
        $this->assertSame('peer needs to update to a compatible cairn version', $e->suggestion());
        $this->assertStringContainsString('peer needs to update', $e->getMessage());
    }

    public function testCustomSuggestionOverridesDefault(): void
    {
        $e = new TransportExhausted('details', 'custom suggestion');
        $this->assertSame('custom suggestion', $e->suggestion);
        $this->assertSame('custom suggestion', $e->suggestion());
    }

    // --- All 8 error types are CairnException subclasses ---

    public function testAllErrorTypesExtendCairnException(): void
    {
        $errors = [
            new TransportExhausted('', ''),
            new SessionExpired('', 0.0),
            new PeerUnreachable('', 0.0),
            new AuthenticationFailed(''),
            new PairingRejected(''),
            new PairingExpired(0.0),
            new MeshRouteNotFound('', ''),
            new VersionMismatch('', '', ''),
        ];

        foreach ($errors as $e) {
            $this->assertInstanceOf(CairnException::class, $e);
            $this->assertInstanceOf(\RuntimeException::class, $e);
        }
    }
}
