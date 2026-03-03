<?php

declare(strict_types=1);

namespace Cairn\Tests\Protocol;

use Cairn\Protocol\MessageType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(MessageType::class)]
final class MessageTypeTest extends TestCase
{
    public function testCategoryVersion(): void
    {
        $this->assertSame('version', MessageType::category(MessageType::VERSION_NEGOTIATE));
    }

    public function testCategoryPairing(): void
    {
        $this->assertSame('pairing', MessageType::category(MessageType::PAIR_REQUEST));
        $this->assertSame('pairing', MessageType::category(MessageType::PAIR_REVOKE));
    }

    public function testCategorySession(): void
    {
        $this->assertSame('session', MessageType::category(MessageType::SESSION_RESUME));
        $this->assertSame('session', MessageType::category(MessageType::SESSION_CLOSE));
    }

    public function testCategoryData(): void
    {
        $this->assertSame('data', MessageType::category(MessageType::DATA_MESSAGE));
        $this->assertSame('data', MessageType::category(MessageType::DATA_NACK));
    }

    public function testCategoryControl(): void
    {
        $this->assertSame('control', MessageType::category(MessageType::HEARTBEAT));
        $this->assertSame('control', MessageType::category(MessageType::TRANSPORT_MIGRATE_ACK));
    }

    public function testCategoryMesh(): void
    {
        $this->assertSame('mesh', MessageType::category(MessageType::ROUTE_REQUEST));
        $this->assertSame('mesh', MessageType::category(MessageType::RELAY_ACK));
    }

    public function testCategoryRendezvous(): void
    {
        $this->assertSame('rendezvous', MessageType::category(MessageType::RENDEZVOUS_PUBLISH));
        $this->assertSame('rendezvous', MessageType::category(MessageType::RENDEZVOUS_RESPONSE));
    }

    public function testCategoryForward(): void
    {
        $this->assertSame('forward', MessageType::category(MessageType::FORWARD_REQUEST));
        $this->assertSame('forward', MessageType::category(MessageType::FORWARD_PURGE));
    }

    public function testCategoryApplication(): void
    {
        $this->assertSame('application', MessageType::category(0xF000));
        $this->assertSame('application', MessageType::category(0xFFFF));
    }

    public function testCategoryReserved(): void
    {
        $this->assertSame('reserved', MessageType::category(0x0800));
    }
}
