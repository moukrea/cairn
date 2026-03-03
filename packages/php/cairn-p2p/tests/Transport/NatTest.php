<?php

declare(strict_types=1);

namespace Cairn\Tests\Transport;

use Cairn\Error\CairnException;
use Cairn\Transport\NatDetector;
use Cairn\Transport\NatType;
use Cairn\Transport\NetworkInfo;

use function Cairn\Transport\STUN_BINDING_REQUEST;
use function Cairn\Transport\STUN_BINDING_RESPONSE;
use function Cairn\Transport\STUN_MAGIC_COOKIE;
use function Cairn\Transport\ATTR_XOR_MAPPED_ADDRESS;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(NatDetector::class)]
#[CoversClass(NetworkInfo::class)]
final class NatTest extends TestCase
{
    public function testNatTypeValues(): void
    {
        $this->assertSame('open', NatType::Open->value);
        $this->assertSame('full_cone', NatType::FullCone->value);
        $this->assertSame('restricted_cone', NatType::RestrictedCone->value);
        $this->assertSame('port_restricted_cone', NatType::PortRestrictedCone->value);
        $this->assertSame('symmetric', NatType::Symmetric->value);
        $this->assertSame('unknown', NatType::Unknown->value);
    }

    public function testNetworkInfoDefaults(): void
    {
        $info = new NetworkInfo();
        $this->assertSame(NatType::Unknown, $info->natType);
        $this->assertNull($info->externalAddr);
    }

    public function testBuildBindingRequest(): void
    {
        $txnId = str_repeat("\x01", 12);
        $request = NatDetector::buildBindingRequest($txnId);

        $this->assertSame(20, strlen($request));

        // Message type: Binding Request (0x0001)
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('n', substr($request, 0, 2));
        $this->assertSame(0x0001, $unpacked[1]);

        // Message length: 0
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('n', substr($request, 2, 2));
        $this->assertSame(0, $unpacked[1]);

        // Magic cookie
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('N', substr($request, 4, 4));
        $this->assertSame(0x2112A442, $unpacked[1]);

        // Transaction ID
        $this->assertSame($txnId, substr($request, 8, 12));
    }

    public function testParseBindingResponseWithXorMappedIpv4(): void
    {
        $txnId = str_repeat("\xAA", 12);

        // Build a STUN Binding Response with XOR-MAPPED-ADDRESS
        $resp = '';
        // Header: type
        $resp .= pack('n', 0x0101); // Binding Response
        // Header: length (placeholder)
        $resp .= pack('n', 0);
        // Header: magic cookie
        $resp .= pack('N', 0x2112A442);
        // Header: transaction ID
        $resp .= $txnId;

        // XOR-MAPPED-ADDRESS attribute
        $resp .= pack('n', 0x0020); // type
        $resp .= pack('n', 8);       // length

        // Family: IPv4
        $resp .= "\x00\x01";

        // XOR port: 12345 XOR (magic_cookie >> 16) = 12345 XOR 0x2112
        $port = 12345;
        $xorPort = $port ^ (0x2112A442 >> 16);
        $resp .= pack('n', $xorPort);

        // XOR IP: 192.168.1.100 XOR magic_cookie
        $ip = (192 << 24) | (168 << 16) | (1 << 8) | 100;
        $xorIp = $ip ^ 0x2112A442;
        $resp .= pack('N', $xorIp);

        // Fix message length
        $msgLen = strlen($resp) - 20;
        $resp = substr($resp, 0, 2) . pack('n', $msgLen) . substr($resp, 4);

        $result = NatDetector::parseBindingResponse($resp, $txnId);
        $this->assertNotNull($result);
        $this->assertSame('192.168.1.100', $result['ip']);
        $this->assertSame(12345, $result['port']);
    }

    public function testParseBindingResponseRejectsTooShort(): void
    {
        $txnId = str_repeat("\x00", 12);
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/too short/');
        NatDetector::parseBindingResponse(str_repeat("\x00", 10), $txnId);
    }

    public function testParseBindingResponseRejectsWrongType(): void
    {
        $txnId = str_repeat("\x00", 12);
        $resp = pack('n', 0x0111) . pack('n', 0) . pack('N', 0x2112A442) . $txnId;

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/unexpected STUN message type/');
        NatDetector::parseBindingResponse($resp, $txnId);
    }

    public function testParseBindingResponseRejectsWrongTxnId(): void
    {
        $txnId = str_repeat("\xBB", 12);
        $wrongTxn = str_repeat("\xCC", 12);
        $resp = pack('n', 0x0101) . pack('n', 0) . pack('N', 0x2112A442) . $wrongTxn;

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/transaction ID mismatch/');
        NatDetector::parseBindingResponse($resp, $txnId);
    }

    public function testDetectWithNoServersReturnsUnknown(): void
    {
        $detector = new NatDetector([], 2.0);
        $info = $detector->detect();
        $this->assertSame(NatType::Unknown, $info->natType);
        $this->assertNull($info->externalAddr);
    }
}
