<?php

declare(strict_types=1);

namespace Cairn\Tests\Pairing;

use Cairn\Error\CairnException;
use Cairn\Pairing\PairingAdapter;
use PHPUnit\Framework\TestCase;

/**
 * A passthrough test adapter that uses simple identity encoding.
 */
final class PassthroughAdapter implements PairingAdapter
{
    public function generatePayload(string $data): string
    {
        return $data;
    }

    public function consumePayload(string $raw): string
    {
        return $raw;
    }

    public function getPakeCredential(string $data): string
    {
        return $data;
    }

    public function name(): string
    {
        return 'passthrough';
    }
}

/**
 * A test adapter that always throws.
 */
final class FailingAdapter implements PairingAdapter
{
    public function generatePayload(string $data): string
    {
        throw new CairnException('device not available');
    }

    public function consumePayload(string $raw): string
    {
        throw new CairnException('invalid format');
    }

    public function getPakeCredential(string $data): string
    {
        throw new CairnException('hardware error');
    }

    public function name(): string
    {
        return 'failing';
    }
}

final class PairingAdapterTest extends TestCase
{
    public function testPassthroughGenerateAndConsume(): void
    {
        $adapter = new PassthroughAdapter();
        $data = "\x01\x02\x03\x04";

        $encoded = $adapter->generatePayload($data);
        $this->assertSame($data, $encoded);

        $decoded = $adapter->consumePayload($encoded);
        $this->assertSame($data, $decoded);
    }

    public function testPassthroughGetPakeCredential(): void
    {
        $adapter = new PassthroughAdapter();
        $data = "\xDE\xAD\xBE\xEF";
        $this->assertSame($data, $adapter->getPakeCredential($data));
    }

    public function testAdapterName(): void
    {
        $this->assertSame('passthrough', (new PassthroughAdapter())->name());
        $this->assertSame('failing', (new FailingAdapter())->name());
    }

    public function testFailingAdapterGenerate(): void
    {
        $adapter = new FailingAdapter();
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/device not available/');
        $adapter->generatePayload('test');
    }

    public function testFailingAdapterConsume(): void
    {
        $adapter = new FailingAdapter();
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/invalid format/');
        $adapter->consumePayload('test');
    }

    public function testFailingAdapterGetPakeCredential(): void
    {
        $adapter = new FailingAdapter();
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/hardware error/');
        $adapter->getPakeCredential('test');
    }
}
