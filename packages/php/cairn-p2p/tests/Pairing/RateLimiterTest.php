<?php

declare(strict_types=1);

namespace Cairn\Tests\Pairing;

use Cairn\Error\CairnException;
use Cairn\Pairing\RateLimiter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RateLimiter::class)]
final class RateLimiterTest extends TestCase
{
    public function testNewCreatesCleanState(): void
    {
        $rl = new RateLimiter();
        $this->assertSame(0, $rl->totalFailures());
        $this->assertFalse($rl->isInvalidated());
    }

    public function testFirstAttemptAllowedWithZeroDelay(): void
    {
        $rl = new RateLimiter();
        $delay = $rl->checkRateLimit('source-1');
        $this->assertSame(0.0, $delay);
    }

    public function testFiveAttemptsAllowedWithinWindow(): void
    {
        $rl = new RateLimiter();
        for ($i = 0; $i < 5; $i++) {
            $rl->checkRateLimit('source-1');
        }
        $this->assertTrue(true); // no exception
    }

    public function testSixthAttemptRejectedWithinWindow(): void
    {
        $rl = new RateLimiter();
        for ($i = 0; $i < 5; $i++) {
            $rl->checkRateLimit('source-1');
        }

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/rate limit exceeded/');
        $rl->checkRateLimit('source-1');
    }

    public function testDifferentSourcesHaveIndependentWindows(): void
    {
        $rl = new RateLimiter();
        for ($i = 0; $i < 5; $i++) {
            $rl->checkRateLimit('source-1');
        }
        // source-2 should still be allowed
        $delay = $rl->checkRateLimit('source-2');
        $this->assertSame(0.0, $delay);
    }

    public function testProgressiveDelayIncreasesWithFailures(): void
    {
        $rl = new RateLimiter();

        // First attempt: no failures yet, zero delay
        $delay = $rl->checkRateLimit('source-1');
        $this->assertSame(0.0, $delay);

        // Record a failure
        $rl->recordFailure('source-1');

        // Second attempt: 1 failure * 2s = 2s delay
        $delay = $rl->checkRateLimit('source-1');
        $this->assertSame(2.0, $delay);

        // Record another failure
        $rl->recordFailure('source-1');

        // Third attempt: 2 failures * 2s = 4s delay
        $delay = $rl->checkRateLimit('source-1');
        $this->assertSame(4.0, $delay);
    }

    public function testRecordSuccessResetsSourceDelay(): void
    {
        $rl = new RateLimiter();

        $rl->checkRateLimit('source-1');
        $rl->recordFailure('source-1');
        $rl->recordFailure('source-1');

        $delay = $rl->checkRateLimit('source-1');
        $this->assertSame(4.0, $delay);

        $rl->recordSuccess('source-1');

        $delay = $rl->checkRateLimit('source-1');
        $this->assertSame(0.0, $delay);
    }

    public function testAutoInvalidationAfterMaxFailures(): void
    {
        $rl = new RateLimiter();

        for ($i = 0; $i < 10; $i++) {
            $source = "source-{$i}";
            $rl->checkRateLimit($source);
            $rl->recordFailure($source);
        }

        $this->assertTrue($rl->isInvalidated());
        $this->assertSame(10, $rl->totalFailures());

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/auto-invalidated/');
        $rl->checkRateLimit('source-new');
    }

    public function testResetClearsAllState(): void
    {
        $rl = new RateLimiter();

        for ($i = 0; $i < 5; $i++) {
            $source = "source-{$i}";
            $rl->checkRateLimit($source);
            $rl->recordFailure($source);
        }

        $this->assertSame(5, $rl->totalFailures());

        $rl->reset();

        $this->assertSame(0, $rl->totalFailures());
        $this->assertFalse($rl->isInvalidated());
        $delay = $rl->checkRateLimit('source-0');
        $this->assertSame(0.0, $delay);
    }

    public function testCustomConfig(): void
    {
        $rl = new RateLimiter(
            maxAttemptsPerWindow: 3,
            windowSeconds: 10,
            maxTotalFailures: 5,
            delayPerFailure: 1.0,
        );

        // 3 attempts allowed
        for ($i = 0; $i < 3; $i++) {
            $rl->checkRateLimit('src');
        }

        // 4th rejected
        $this->expectException(CairnException::class);
        $rl->checkRateLimit('src');
    }

    public function testCustomDelayPerFailure(): void
    {
        $rl = new RateLimiter(
            maxAttemptsPerWindow: 10,
            windowSeconds: 60,
            maxTotalFailures: 20,
            delayPerFailure: 3.0,
        );

        $rl->checkRateLimit('src');
        $rl->recordFailure('src');

        $delay = $rl->checkRateLimit('src');
        $this->assertSame(3.0, $delay);

        $rl->recordFailure('src');
        $delay = $rl->checkRateLimit('src');
        $this->assertSame(6.0, $delay);
    }

    public function testTotalFailuresAcrossSources(): void
    {
        $rl = new RateLimiter();

        $rl->checkRateLimit('a');
        $rl->recordFailure('a');

        $rl->checkRateLimit('b');
        $rl->recordFailure('b');

        $rl->checkRateLimit('c');
        $rl->recordFailure('c');

        $this->assertSame(3, $rl->totalFailures());
    }

    public function testSuccessDoesNotReduceTotalFailures(): void
    {
        $rl = new RateLimiter();

        $rl->checkRateLimit('src');
        $rl->recordFailure('src');
        $this->assertSame(1, $rl->totalFailures());

        $rl->recordSuccess('src');
        // Total failures remain (they accumulate toward auto-invalidation)
        $this->assertSame(1, $rl->totalFailures());
    }

    public function testRecordSuccessOnUnknownSourceIsNoop(): void
    {
        $rl = new RateLimiter();
        $rl->recordSuccess('nonexistent');
        $this->assertSame(0, $rl->totalFailures());
    }

    public function testCustomMaxFailuresThreshold(): void
    {
        $rl = new RateLimiter(
            maxAttemptsPerWindow: 10,
            windowSeconds: 60,
            maxTotalFailures: 5,
        );

        for ($i = 0; $i < 5; $i++) {
            $source = "s-{$i}";
            $rl->checkRateLimit($source);
            $rl->recordFailure($source);
        }

        $this->assertTrue($rl->isInvalidated());
    }
}
