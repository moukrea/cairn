<?php

declare(strict_types=1);

namespace Cairn\Tests\Server;

use Cairn\Crypto\Identity;
use Cairn\Crypto\PeerId;
use Cairn\Server\DeduplicationTracker;
use Cairn\Server\ForwardAck;
use Cairn\Server\ForwardDeliver;
use Cairn\Server\ForwardPurge;
use Cairn\Server\ForwardRequest;
use Cairn\Server\MessageQueue;
use Cairn\Server\RetentionPolicy;
use Cairn\Server\StoredMessage;

use function Cairn\Server\FORWARD_CHANNEL;
use function Cairn\Server\MAX_SKIP_THRESHOLD;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(MessageQueue::class)]
#[CoversClass(ForwardRequest::class)]
#[CoversClass(ForwardAck::class)]
#[CoversClass(ForwardDeliver::class)]
#[CoversClass(ForwardPurge::class)]
#[CoversClass(RetentionPolicy::class)]
#[CoversClass(StoredMessage::class)]
#[CoversClass(DeduplicationTracker::class)]
final class ForwardTest extends TestCase
{
    private function makePeer(int $seed): PeerId
    {
        return Identity::fromSeed(str_repeat(chr($seed), 32))->peerId();
    }

    /**
     * @return array<string, true>
     */
    private function makePairedSet(PeerId ...$peers): array
    {
        $set = [];
        foreach ($peers as $peer) {
            $set[(string) $peer] = true;
        }
        return $set;
    }

    private function makeRequest(PeerId $recipient, int $seq): ForwardRequest
    {
        return new ForwardRequest(
            msgId: bin2hex(random_bytes(16)),
            recipient: $recipient,
            encryptedPayload: str_repeat("\xAB", 64),
            sequenceNumber: $seq,
        );
    }

    // --- Constants ---

    public function testForwardChannelConstant(): void
    {
        $this->assertSame('__cairn_forward', FORWARD_CHANNEL);
    }

    public function testMaxSkipThresholdIs1000(): void
    {
        $this->assertSame(1000, MAX_SKIP_THRESHOLD);
    }

    // --- RetentionPolicy ---

    public function testDefaultRetentionPolicy(): void
    {
        $policy = new RetentionPolicy();
        $this->assertSame(604800, $policy->maxAge); // 7 days
        $this->assertSame(1000, $policy->maxMessages);
    }

    // --- Enqueue ---

    public function testEnqueueAccepted(): void
    {
        $queue = new MessageQueue();
        $sender = $this->makePeer(1);
        $recipient = $this->makePeer(2);
        $paired = $this->makePairedSet($sender, $recipient);
        $req = $this->makeRequest($recipient, 1);

        $ack = $queue->enqueue($req, $sender, $paired);
        $this->assertTrue($ack->accepted);
        $this->assertNull($ack->rejectionReason);
        $this->assertSame(1, $queue->queueDepth($recipient));
    }

    public function testEnqueueRejectsUnpairedSender(): void
    {
        $queue = new MessageQueue();
        $sender = $this->makePeer(1);
        $recipient = $this->makePeer(2);
        $paired = $this->makePairedSet($recipient); // sender not paired

        $ack = $queue->enqueue($this->makeRequest($recipient, 1), $sender, $paired);
        $this->assertFalse($ack->accepted);
        $this->assertStringContainsString('sender', $ack->rejectionReason);
    }

    public function testEnqueueRejectsUnpairedRecipient(): void
    {
        $queue = new MessageQueue();
        $sender = $this->makePeer(1);
        $recipient = $this->makePeer(2);
        $paired = $this->makePairedSet($sender); // recipient not paired

        $ack = $queue->enqueue($this->makeRequest($recipient, 1), $sender, $paired);
        $this->assertFalse($ack->accepted);
        $this->assertStringContainsString('recipient', $ack->rejectionReason);
    }

    public function testEnqueueRejectsDuplicateMsgId(): void
    {
        $queue = new MessageQueue();
        $sender = $this->makePeer(1);
        $recipient = $this->makePeer(2);
        $paired = $this->makePairedSet($sender, $recipient);
        $req = $this->makeRequest($recipient, 1);

        $queue->enqueue($req, $sender, $paired);
        $ack2 = $queue->enqueue($req, $sender, $paired);
        $this->assertFalse($ack2->accepted);
        $this->assertStringContainsString('duplicate', $ack2->rejectionReason);
    }

    public function testEnqueueRejectsQueueFull(): void
    {
        $policy = new RetentionPolicy(maxAge: 86400, maxMessages: 3);
        $queue = new MessageQueue($policy);
        $sender = $this->makePeer(1);
        $recipient = $this->makePeer(2);
        $paired = $this->makePairedSet($sender, $recipient);

        for ($seq = 1; $seq <= 3; $seq++) {
            $ack = $queue->enqueue($this->makeRequest($recipient, $seq), $sender, $paired);
            $this->assertTrue($ack->accepted);
        }

        $ack = $queue->enqueue($this->makeRequest($recipient, 4), $sender, $paired);
        $this->assertFalse($ack->accepted);
        $this->assertStringContainsString('queue full', $ack->rejectionReason);
    }

    public function testEnqueueRejectsSequenceGapExceedingThreshold(): void
    {
        $queue = new MessageQueue();
        $sender = $this->makePeer(1);
        $recipient = $this->makePeer(2);
        $paired = $this->makePairedSet($sender, $recipient);

        $queue->enqueue($this->makeRequest($recipient, 1), $sender, $paired);

        // Gap of 1001 exceeds MAX_SKIP_THRESHOLD (1000)
        $ack = $queue->enqueue($this->makeRequest($recipient, 1002), $sender, $paired);
        $this->assertFalse($ack->accepted);
        $this->assertStringContainsString('skip threshold', $ack->rejectionReason);
    }

    public function testEnqueueAllowsSequenceGapWithinThreshold(): void
    {
        $queue = new MessageQueue();
        $sender = $this->makePeer(1);
        $recipient = $this->makePeer(2);
        $paired = $this->makePairedSet($sender, $recipient);

        $queue->enqueue($this->makeRequest($recipient, 1), $sender, $paired);

        // Gap of exactly 1000 is within threshold
        $ack = $queue->enqueue($this->makeRequest($recipient, 1001), $sender, $paired);
        $this->assertTrue($ack->accepted);
    }

    // --- Delivery ---

    public function testDeliverReturnsMessagesInOrder(): void
    {
        $queue = new MessageQueue();
        $sender = $this->makePeer(1);
        $recipient = $this->makePeer(2);
        $paired = $this->makePairedSet($sender, $recipient);

        for ($seq = 1; $seq <= 5; $seq++) {
            $queue->enqueue($this->makeRequest($recipient, $seq), $sender, $paired);
        }

        [$delivers, $purge] = $queue->deliver($recipient);
        $this->assertCount(5, $delivers);
        $this->assertCount(5, $purge->msgIds);

        foreach ($delivers as $i => $deliver) {
            $this->assertSame($i + 1, $deliver->sequenceNumber);
            $this->assertTrue($deliver->sender->equals($sender));
        }
        $this->assertSame(0, $queue->queueDepth($recipient));
    }

    public function testDeliverEmptyQueue(): void
    {
        $queue = new MessageQueue();
        $recipient = $this->makePeer(2);

        [$delivers, $purge] = $queue->deliver($recipient);
        $this->assertCount(0, $delivers);
        $this->assertCount(0, $purge->msgIds);
    }

    public function testDeliverClearsDedupEntries(): void
    {
        $queue = new MessageQueue();
        $sender = $this->makePeer(1);
        $recipient = $this->makePeer(2);
        $paired = $this->makePairedSet($sender, $recipient);

        $req = $this->makeRequest($recipient, 1);
        $msgId = $req->msgId;
        $queue->enqueue($req, $sender, $paired);
        $queue->deliver($recipient);

        // Same msg_id should be accepted again after delivery purge
        $req2 = new ForwardRequest(
            msgId: $msgId,
            recipient: $recipient,
            encryptedPayload: str_repeat("\xCD", 32),
            sequenceNumber: 2,
        );
        $ack = $queue->enqueue($req2, $sender, $paired);
        $this->assertTrue($ack->accepted);
    }

    // --- Per-peer override ---

    public function testPerPeerOverride(): void
    {
        $defaultPolicy = new RetentionPolicy(maxAge: 86400, maxMessages: 2);
        $queue = new MessageQueue($defaultPolicy);
        $sender = $this->makePeer(1);
        $priorityPeer = $this->makePeer(2);
        $regularPeer = $this->makePeer(3);
        $paired = $this->makePairedSet($sender, $priorityPeer, $regularPeer);

        // Give priority_peer a higher quota
        $queue->setPeerOverride($priorityPeer, new RetentionPolicy(maxAge: 86400, maxMessages: 100));

        // Regular peer should hit cap at 2
        for ($seq = 1; $seq <= 3; $seq++) {
            $queue->enqueue($this->makeRequest($regularPeer, $seq), $sender, $paired);
        }
        $this->assertSame(2, $queue->queueDepth($regularPeer)); // capped

        // Priority peer should accept all 3
        for ($seq = 1; $seq <= 3; $seq++) {
            $queue->enqueue($this->makeRequest($priorityPeer, $seq), $sender, $paired);
        }
        $this->assertSame(3, $queue->queueDepth($priorityPeer));
    }

    // --- Total messages ---

    public function testTotalMessagesAcrossPeers(): void
    {
        $queue = new MessageQueue();
        $sender = $this->makePeer(1);
        $r1 = $this->makePeer(2);
        $r2 = $this->makePeer(3);
        $paired = $this->makePairedSet($sender, $r1, $r2);

        for ($seq = 1; $seq <= 3; $seq++) {
            $queue->enqueue($this->makeRequest($r1, $seq), $sender, $paired);
        }
        for ($seq = 1; $seq <= 2; $seq++) {
            $queue->enqueue($this->makeRequest($r2, $seq), $sender, $paired);
        }
        $this->assertSame(5, $queue->totalMessages());
    }

    // --- Forward message types ---

    public function testForwardRequestFields(): void
    {
        $recipient = $this->makePeer(1);
        $req = new ForwardRequest(
            msgId: 'test-id',
            recipient: $recipient,
            encryptedPayload: "\x01\x02\x03",
            sequenceNumber: 42,
        );
        $this->assertTrue($req->recipient->equals($recipient));
        $this->assertSame(42, $req->sequenceNumber);
        $this->assertSame("\x01\x02\x03", $req->encryptedPayload);
    }

    public function testForwardAckAccepted(): void
    {
        $ack = new ForwardAck(msgId: 'test-id', accepted: true);
        $this->assertTrue($ack->accepted);
        $this->assertNull($ack->rejectionReason);
    }

    public function testForwardAckRejected(): void
    {
        $ack = new ForwardAck(msgId: 'test-id', accepted: false, rejectionReason: 'test reason');
        $this->assertFalse($ack->accepted);
        $this->assertSame('test reason', $ack->rejectionReason);
    }

    public function testForwardDeliverFields(): void
    {
        $sender = $this->makePeer(1);
        $deliver = new ForwardDeliver(
            msgId: 'test-id',
            sender: $sender,
            encryptedPayload: "\xDE\xAD",
            sequenceNumber: 99,
        );
        $this->assertTrue($deliver->sender->equals($sender));
        $this->assertSame(99, $deliver->sequenceNumber);
    }

    public function testForwardPurgeFields(): void
    {
        $purge = new ForwardPurge(['id-1', 'id-2']);
        $this->assertCount(2, $purge->msgIds);
    }

    // --- DeduplicationTracker ---

    public function testDedupTrackerNewMessage(): void
    {
        $tracker = new DeduplicationTracker(100);
        $this->assertTrue($tracker->checkAndInsert('msg-1'));
        $this->assertSame(1, $tracker->count());
    }

    public function testDedupTrackerRejectsDuplicate(): void
    {
        $tracker = new DeduplicationTracker(100);
        $this->assertTrue($tracker->checkAndInsert('msg-1'));
        $this->assertFalse($tracker->checkAndInsert('msg-1'));
        $this->assertSame(1, $tracker->count());
    }

    public function testDedupTrackerEvictsOldest(): void
    {
        $tracker = new DeduplicationTracker(3);
        $tracker->checkAndInsert('id-1');
        $tracker->checkAndInsert('id-2');
        $tracker->checkAndInsert('id-3');
        $this->assertSame(3, $tracker->count());

        // Adding id-4 should evict id-1
        $tracker->checkAndInsert('id-4');
        $this->assertSame(3, $tracker->count());

        // id-1 should now be accepted again
        $this->assertTrue($tracker->checkAndInsert('id-1'));
    }

    public function testDedupTrackerIsEmpty(): void
    {
        $tracker = new DeduplicationTracker(10);
        $this->assertTrue($tracker->isEmpty());
    }
}
