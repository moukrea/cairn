<?php

declare(strict_types=1);

namespace Cairn\Tests;

use Cairn\Channel;
use Cairn\ChannelManager;
use Cairn\ChannelState;
use Cairn\DataAck;
use Cairn\DataMessage;
use Cairn\DataNack;
use Cairn\Error\CairnException;

use function Cairn\validateChannelName;

use const Cairn\CHANNEL_FORWARD;
use const Cairn\RESERVED_CHANNEL_PREFIX;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Channel::class)]
#[CoversClass(ChannelManager::class)]
#[CoversClass(DataMessage::class)]
final class ChannelTest extends TestCase
{
    // --- Reserved name validation ---

    public function testValidateChannelNameValid(): void
    {
        validateChannelName('my-channel');
        validateChannelName('data');
        validateChannelName('chat_room_1');
        $this->assertTrue(true); // no exception means pass
    }

    public function testValidateChannelNameReservedPrefixRejected(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/reserved prefix/');
        validateChannelName('__cairn_forward');
    }

    public function testValidateChannelNameReservedCustomRejected(): void
    {
        $this->expectException(CairnException::class);
        validateChannelName('__cairn_custom');
    }

    public function testValidateChannelNameEmptyRejected(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/must not be empty/');
        validateChannelName('');
    }

    public function testReservedConstants(): void
    {
        $this->assertSame('__cairn_', RESERVED_CHANNEL_PREFIX);
        $this->assertSame('__cairn_forward', CHANNEL_FORWARD);
        $this->assertTrue(str_starts_with(CHANNEL_FORWARD, RESERVED_CHANNEL_PREFIX));
    }

    // --- Channel state transitions ---

    public function testChannelNewIsOpening(): void
    {
        $ch = new Channel('test', 1);
        $this->assertSame(ChannelState::Opening, $ch->state());
        $this->assertSame('test', $ch->name);
        $this->assertSame(1, $ch->streamId);
        $this->assertFalse($ch->isOpen());
    }

    public function testChannelAccept(): void
    {
        $ch = new Channel('test', 1);
        $ch->accept();
        $this->assertSame(ChannelState::Open, $ch->state());
        $this->assertTrue($ch->isOpen());
    }

    public function testChannelReject(): void
    {
        $ch = new Channel('test', 1);
        $ch->reject();
        $this->assertSame(ChannelState::Rejected, $ch->state());
        $this->assertFalse($ch->isOpen());
    }

    public function testChannelCloseFromOpen(): void
    {
        $ch = new Channel('test', 1);
        $ch->accept();
        $ch->close();
        $this->assertSame(ChannelState::Closed, $ch->state());
        $this->assertFalse($ch->isOpen());
    }

    public function testChannelCloseFromOpening(): void
    {
        $ch = new Channel('test', 1);
        $ch->close();
        $this->assertSame(ChannelState::Closed, $ch->state());
    }

    public function testChannelDoubleAcceptRejected(): void
    {
        $ch = new Channel('test', 1);
        $ch->accept();
        $this->expectException(CairnException::class);
        $ch->accept();
    }

    public function testChannelAcceptAfterRejectRejected(): void
    {
        $ch = new Channel('test', 1);
        $ch->reject();
        $this->expectException(CairnException::class);
        $ch->accept();
    }

    public function testChannelDoubleCloseRejected(): void
    {
        $ch = new Channel('test', 1);
        $ch->close();
        $this->expectException(CairnException::class);
        $ch->close();
    }

    public function testChannelWithMetadata(): void
    {
        $ch = new Channel('test', 1, "\xCA\xFE");
        $this->assertSame("\xCA\xFE", $ch->metadata);
    }

    // --- DataMessage ---

    public function testDataMessageCreate(): void
    {
        $msg = DataMessage::create('hello');
        $this->assertSame('hello', $msg->payload);
        $this->assertSame(16, strlen($msg->msgId));
    }

    public function testDataMessageUniqueIds(): void
    {
        $msg1 = DataMessage::create('');
        $msg2 = DataMessage::create('');
        $this->assertNotSame($msg1->msgId, $msg2->msgId);
    }

    public function testDataAck(): void
    {
        $msg = DataMessage::create('data');
        $ack = new DataAck($msg->msgId);
        $this->assertSame($msg->msgId, $ack->ackedMsgId);
    }

    public function testDataNack(): void
    {
        $msg = DataMessage::create('data');
        $nack = new DataNack($msg->msgId, 'checksum mismatch');
        $this->assertSame($msg->msgId, $nack->nackedMsgId);
        $this->assertSame('checksum mismatch', $nack->reason);
    }

    public function testDataNackNoReason(): void
    {
        $nack = new DataNack(str_repeat("\x00", 16));
        $this->assertNull($nack->reason);
    }

    // --- ChannelManager ---

    public function testChannelManagerOpen(): void
    {
        $mgr = new ChannelManager();
        $ch = $mgr->openChannel('chat');
        $this->assertSame('chat', $ch->name);
        $this->assertSame(1, $mgr->channelCount());
        $this->assertSame(ChannelState::Opening, $ch->state());
    }

    public function testChannelManagerOpenReservedRejected(): void
    {
        $mgr = new ChannelManager();
        $this->expectException(CairnException::class);
        $mgr->openChannel('__cairn_forward');
    }

    public function testChannelManagerHandleInit(): void
    {
        $mgr = new ChannelManager();
        /** @var list<Channel> $opened */
        $opened = [];
        $mgr->on('channel_opened', function (Channel $ch) use (&$opened): void {
            $opened[] = $ch;
        });

        $ch = $mgr->handleChannelInit(5, 'remote-channel', "\xAB");

        $this->assertSame(1, $mgr->channelCount());
        $this->assertSame('remote-channel', $ch->name);
        $this->assertSame(5, $ch->streamId);
        $this->assertSame(ChannelState::Opening, $ch->state());
        $this->assertCount(1, $opened);
        $this->assertSame('remote-channel', $opened[0]->name);
    }

    public function testChannelManagerDuplicateStreamRejected(): void
    {
        $mgr = new ChannelManager();
        $mgr->handleChannelInit(1, 'ch1');
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/already has a channel/');
        $mgr->handleChannelInit(1, 'ch2');
    }

    public function testChannelManagerAccept(): void
    {
        $mgr = new ChannelManager();
        /** @var list<Channel> $accepted */
        $accepted = [];
        $mgr->on('channel_accepted', function (Channel $ch) use (&$accepted): void {
            $accepted[] = $ch;
        });

        $mgr->handleChannelInit(1, 'ch');
        $mgr->acceptChannel(1);

        $ch = $mgr->getChannel(1);
        $this->assertNotNull($ch);
        $this->assertSame(ChannelState::Open, $ch->state());
        $this->assertCount(1, $accepted);
    }

    public function testChannelManagerReject(): void
    {
        $mgr = new ChannelManager();
        /** @var list<array{Channel, ?string}> $rejected */
        $rejected = [];
        $mgr->on('channel_rejected', function (Channel $ch, ?string $reason) use (&$rejected): void {
            $rejected[] = [$ch, $reason];
        });

        $mgr->handleChannelInit(1, 'ch');
        $mgr->rejectChannel(1, 'not allowed');

        $ch = $mgr->getChannel(1);
        $this->assertNotNull($ch);
        $this->assertSame(ChannelState::Rejected, $ch->state());
        $this->assertCount(1, $rejected);
        $this->assertSame('not allowed', $rejected[0][1]);
    }

    public function testChannelManagerDataOnOpenChannel(): void
    {
        $mgr = new ChannelManager();
        /** @var list<array{Channel, DataMessage}> $dataEvents */
        $dataEvents = [];
        $mgr->on('channel_data', function (Channel $ch, DataMessage $msg) use (&$dataEvents): void {
            $dataEvents[] = [$ch, $msg];
        });

        $mgr->handleChannelInit(1, 'data');
        $mgr->acceptChannel(1);

        $msg = DataMessage::create("\x42");
        $mgr->handleData(1, $msg);

        $this->assertCount(1, $dataEvents);
        $this->assertSame("\x42", $dataEvents[0][1]->payload);
    }

    public function testChannelManagerDataOnNonOpenRejected(): void
    {
        $mgr = new ChannelManager();
        $mgr->handleChannelInit(1, 'data');
        $msg = DataMessage::create("\x42");
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/not open/');
        $mgr->handleData(1, $msg);
    }

    public function testChannelManagerDataOnUnknownStreamRejected(): void
    {
        $mgr = new ChannelManager();
        $msg = DataMessage::create("\x42");
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/no channel on stream/');
        $mgr->handleData(99, $msg);
    }

    public function testChannelManagerClose(): void
    {
        $mgr = new ChannelManager();
        /** @var list<Channel> $closed */
        $closed = [];
        $mgr->on('channel_closed', function (Channel $ch) use (&$closed): void {
            $closed[] = $ch;
        });

        $mgr->handleChannelInit(1, 'ch');
        $mgr->acceptChannel(1);
        $mgr->closeChannel(1);

        $ch = $mgr->getChannel(1);
        $this->assertNotNull($ch);
        $this->assertSame(ChannelState::Closed, $ch->state());
        $this->assertCount(1, $closed);
    }

    public function testChannelManagerMultipleChannels(): void
    {
        $mgr = new ChannelManager();
        $mgr->openChannel('ch1');
        $mgr->openChannel('ch2');
        $mgr->openChannel('ch3');
        $this->assertSame(3, $mgr->channelCount());
    }

    public function testChannelManagerOpenWithMetadata(): void
    {
        $mgr = new ChannelManager();
        $ch = $mgr->openChannel('meta-ch', "\x01\x02");
        $this->assertSame("\x01\x02", $ch->metadata);
    }

    public function testChannelManagerGetNonExistent(): void
    {
        $mgr = new ChannelManager();
        $this->assertNull($mgr->getChannel(999));
    }
}
