"""Tests for reconnection: backoff, heartbeat, message queue, network change."""

import time

import pytest

from cairn.transport.heartbeat import (
    BackoffConfig,
    BackoffState,
    EnqueueResult,
    HeartbeatConfig,
    HeartbeatMonitor,
    MessageQueue,
    NetworkChange,
    NetworkChangeType,
    QueueConfig,
    QueueStrategy,
)


class TestHeartbeatConfig:
    def test_defaults(self):
        cfg = HeartbeatConfig()
        assert cfg.interval == 30.0
        assert cfg.timeout == 90.0

    def test_aggressive(self):
        cfg = HeartbeatConfig.aggressive()
        assert cfg.interval == 5.0
        assert cfg.timeout == 15.0

    def test_relaxed(self):
        cfg = HeartbeatConfig.relaxed()
        assert cfg.interval == 60.0
        assert cfg.timeout == 180.0

    def test_timeout_3x_interval(self):
        for cfg in [
            HeartbeatConfig(),
            HeartbeatConfig.aggressive(),
            HeartbeatConfig.relaxed(),
        ]:
            assert cfg.timeout == cfg.interval * 3


class TestHeartbeatMonitor:
    def test_not_timed_out_initially(self):
        mon = HeartbeatMonitor()
        assert not mon.is_timed_out()

    def test_not_needing_heartbeat_initially(self):
        mon = HeartbeatMonitor()
        assert not mon.should_send_heartbeat()

    def test_time_until_heartbeat_positive(self):
        mon = HeartbeatMonitor()
        t = mon.time_until_next_heartbeat()
        assert 0 < t <= 30.0

    def test_time_until_timeout_positive(self):
        mon = HeartbeatMonitor()
        t = mon.time_until_timeout()
        assert 0 < t <= 90.0

    def test_timed_out_with_zero_timeout(self):
        cfg = HeartbeatConfig(interval=1.0, timeout=0.0)
        mon = HeartbeatMonitor(cfg)
        assert mon.is_timed_out()

    def test_should_send_with_zero_interval(self):
        cfg = HeartbeatConfig(interval=0.0, timeout=10.0)
        mon = HeartbeatMonitor(cfg)
        assert mon.should_send_heartbeat()

    def test_record_activity_resets_timeout(self):
        cfg = HeartbeatConfig(interval=1.0, timeout=0.0)
        mon = HeartbeatMonitor(cfg)
        assert mon.is_timed_out()
        mon._config.timeout = 60.0
        mon.record_activity()
        assert not mon.is_timed_out()

    def test_record_heartbeat_sent(self):
        cfg = HeartbeatConfig(interval=0.0, timeout=10.0)
        mon = HeartbeatMonitor(cfg)
        assert mon.should_send_heartbeat()
        mon._config.interval = 30.0
        mon.record_heartbeat_sent()
        assert not mon.should_send_heartbeat()

    def test_config_accessible(self):
        cfg = HeartbeatConfig.aggressive()
        mon = HeartbeatMonitor(cfg)
        assert mon.config.interval == 5.0
        assert mon.config.timeout == 15.0

    def test_last_activity_recent(self):
        mon = HeartbeatMonitor()
        assert time.monotonic() - mon.last_activity < 1.0


class TestBackoffConfig:
    def test_defaults(self):
        cfg = BackoffConfig()
        assert cfg.initial_delay == 1.0
        assert cfg.max_delay == 60.0
        assert abs(cfg.factor - 2.0) < 1e-9

    def test_custom(self):
        cfg = BackoffConfig(
            initial_delay=0.1, max_delay=5.0, factor=3.0
        )
        assert cfg.initial_delay == 0.1
        assert cfg.max_delay == 5.0
        assert abs(cfg.factor - 3.0) < 1e-9


class TestBackoffState:
    def test_sequence_no_jitter(self):
        state = BackoffState(BackoffConfig())
        assert state.next_delay_no_jitter() == 1.0
        assert state.next_delay_no_jitter() == 2.0
        assert state.next_delay_no_jitter() == 4.0
        assert state.next_delay_no_jitter() == 8.0
        assert state.attempt == 4

    def test_max_delay_cap(self):
        state = BackoffState(BackoffConfig())
        for _ in range(10):
            state.next_delay_no_jitter()
        delay = state.next_delay_no_jitter()
        assert delay == 60.0

    def test_reset(self):
        state = BackoffState(BackoffConfig())
        state.next_delay_no_jitter()
        state.next_delay_no_jitter()
        assert state.attempt == 2
        state.reset()
        assert state.attempt == 0
        assert state.next_delay_no_jitter() == 1.0

    def test_custom_config(self):
        cfg = BackoffConfig(
            initial_delay=0.1, max_delay=5.0, factor=3.0
        )
        state = BackoffState(cfg)
        assert state.next_delay_no_jitter() == pytest.approx(0.1)
        assert state.next_delay_no_jitter() == pytest.approx(0.3)
        assert state.next_delay_no_jitter() == pytest.approx(0.9)
        assert state.next_delay_no_jitter() == pytest.approx(2.7)
        assert state.next_delay_no_jitter() == 5.0

    def test_jitter_adds_randomness(self):
        delays = [BackoffState(BackoffConfig()).next_delay() for _ in range(20)]
        # With jitter, not all delays should be identical
        assert len(set(delays)) > 1

    def test_jitter_bounded(self):
        for _ in range(100):
            s = BackoffState(BackoffConfig())
            d = s.next_delay()
            # initial=1s, max jitter = 0.5*1 = 0.5, so d in [1.0, 1.5]
            assert 1.0 <= d <= 1.5

    def test_config_accessible(self):
        cfg = BackoffConfig(initial_delay=2.0)
        state = BackoffState(cfg)
        assert state.config.initial_delay == 2.0


class TestQueueConfig:
    def test_defaults(self):
        cfg = QueueConfig()
        assert cfg.enabled
        assert cfg.max_size == 1000
        assert cfg.max_age == 3600.0
        assert cfg.strategy == QueueStrategy.FIFO

    def test_strategy_display(self):
        assert str(QueueStrategy.FIFO) == "FIFO"
        assert str(QueueStrategy.LIFO) == "LIFO"


class TestMessageQueue:
    def test_starts_empty(self):
        q = MessageQueue()
        assert q.is_empty
        assert len(q) == 0
        assert q.remaining_capacity == 1000

    def test_enqueue_success(self):
        q = MessageQueue()
        result = q.enqueue(1, b"\x01\x02\x03")
        assert result == EnqueueResult.ENQUEUED
        assert len(q) == 1
        assert not q.is_empty

    def test_enqueue_multiple(self):
        q = MessageQueue()
        q.enqueue(1, b"\x01")
        q.enqueue(2, b"\x02")
        q.enqueue(3, b"\x03")
        assert len(q) == 3
        assert q.remaining_capacity == 997

    def test_peek(self):
        q = MessageQueue()
        assert q.peek() is None
        q.enqueue(1, b"\x0a\x14")
        msg = q.peek()
        assert msg.sequence == 1
        assert msg.payload == b"\x0a\x14"
        assert len(q) == 1  # peek doesn't consume

    def test_enqueue_disabled(self):
        cfg = QueueConfig(enabled=False)
        q = MessageQueue(cfg)
        result = q.enqueue(1, b"\x01")
        assert result == EnqueueResult.DISABLED
        assert q.is_empty

    def test_fifo_rejects_when_full(self):
        cfg = QueueConfig(max_size=3, strategy=QueueStrategy.FIFO)
        q = MessageQueue(cfg)
        assert q.enqueue(1, b"\x01") == EnqueueResult.ENQUEUED
        assert q.enqueue(2, b"\x02") == EnqueueResult.ENQUEUED
        assert q.enqueue(3, b"\x03") == EnqueueResult.ENQUEUED
        assert q.enqueue(4, b"\x04") == EnqueueResult.FULL
        assert len(q) == 3
        assert q.peek().sequence == 1

    def test_lifo_evicts_oldest(self):
        cfg = QueueConfig(max_size=3, strategy=QueueStrategy.LIFO)
        q = MessageQueue(cfg)
        q.enqueue(1, b"\x01")
        q.enqueue(2, b"\x02")
        q.enqueue(3, b"\x03")
        result = q.enqueue(4, b"\x04")
        assert result == EnqueueResult.ENQUEUED_WITH_EVICTION
        assert len(q) == 3
        assert q.peek().sequence == 2

    def test_lifo_multiple_evictions(self):
        cfg = QueueConfig(max_size=2, strategy=QueueStrategy.LIFO)
        q = MessageQueue(cfg)
        q.enqueue(1, b"\x01")
        q.enqueue(2, b"\x02")
        q.enqueue(3, b"\x03")  # evicts 1
        q.enqueue(4, b"\x04")  # evicts 2
        assert len(q) == 2
        msgs = q.drain()
        assert msgs[0].sequence == 3
        assert msgs[1].sequence == 4

    def test_drain_returns_in_order(self):
        q = MessageQueue()
        q.enqueue(1, b"\x0a")
        q.enqueue(2, b"\x14")
        q.enqueue(3, b"\x1e")
        msgs = q.drain()
        assert len(msgs) == 3
        assert msgs[0].sequence == 1
        assert msgs[1].sequence == 2
        assert msgs[2].sequence == 3
        assert q.is_empty

    def test_clear_discards_all(self):
        q = MessageQueue()
        q.enqueue(1, b"\x01")
        q.enqueue(2, b"\x02")
        assert len(q) == 2
        q.clear()
        assert q.is_empty
        assert q.remaining_capacity == 1000

    def test_expire_stale_with_zero_max_age(self):
        cfg = QueueConfig(max_age=0.0)
        q = MessageQueue(cfg)
        q.enqueue(1, b"\x01")
        q.enqueue(2, b"\x02")
        msgs = q.drain()
        assert len(msgs) == 0

    def test_messages_maintain_insertion_order(self):
        q = MessageQueue()
        for seq in range(9, -1, -1):
            q.enqueue(seq, bytes([seq]))
        msgs = q.drain()
        for i, msg in enumerate(msgs):
            assert msg.sequence == 9 - i

    def test_payload_preserved(self):
        q = MessageQueue()
        payload = b"\xDE\xAD\xBE\xEF"
        q.enqueue(42, payload)
        msgs = q.drain()
        assert msgs[0].payload == payload
        assert msgs[0].sequence == 42

    def test_remaining_capacity_decreases(self):
        cfg = QueueConfig(max_size=5)
        q = MessageQueue(cfg)
        assert q.remaining_capacity == 5
        q.enqueue(1, b"")
        assert q.remaining_capacity == 4
        q.enqueue(2, b"")
        q.enqueue(3, b"")
        assert q.remaining_capacity == 2


class TestNetworkChange:
    def test_interface_up_display(self):
        nc = NetworkChange(
            NetworkChangeType.INTERFACE_UP, "wlan0"
        )
        assert str(nc) == "interface up: wlan0"

    def test_interface_down_display(self):
        nc = NetworkChange(
            NetworkChangeType.INTERFACE_DOWN, "eth0"
        )
        assert str(nc) == "interface down: eth0"

    def test_address_changed_display(self):
        nc = NetworkChange(
            NetworkChangeType.ADDRESS_CHANGED,
            "wlan0",
            old_addr="192.168.1.10",
            new_addr="10.0.0.5",
        )
        assert str(nc) == "address changed on wlan0: 10.0.0.5"
