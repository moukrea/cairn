"""Tests for session management and channel multiplexing."""

import asyncio
import time

import pytest

from cairn.channel import (
    CHANNEL_FORWARD,
    RESERVED_CHANNEL_PREFIX,
    Channel,
    ChannelInit,
    ChannelManager,
    ChannelState,
    validate_channel_name,
)
from cairn.crypto.identity import IdentityKeypair
from cairn.session import (
    Session,
    SessionConfig,
    SessionState,
    SessionStateMachine,
)


class TestSessionStateMachine:
    def test_initial_state(self):
        sm = SessionStateMachine()
        assert sm.state == SessionState.CONNECTED
        assert len(sm.session_id) == 16

    def test_custom_initial_state(self):
        sm = SessionStateMachine(
            initial_state=SessionState.DISCONNECTED
        )
        assert sm.state == SessionState.DISCONNECTED

    def test_valid_connected_to_unstable(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.UNSTABLE)
        assert sm.state == SessionState.UNSTABLE

    def test_valid_connected_to_disconnected(self):
        sm = SessionStateMachine()
        sm.transition(
            SessionState.DISCONNECTED, reason="abrupt loss"
        )
        assert sm.state == SessionState.DISCONNECTED

    def test_valid_unstable_to_connected(self):
        sm = SessionStateMachine(
            initial_state=SessionState.UNSTABLE
        )
        sm.transition(SessionState.CONNECTED)
        assert sm.state == SessionState.CONNECTED

    def test_valid_unstable_to_disconnected(self):
        sm = SessionStateMachine(
            initial_state=SessionState.UNSTABLE
        )
        sm.transition(SessionState.DISCONNECTED)
        assert sm.state == SessionState.DISCONNECTED

    def test_valid_disconnected_to_reconnecting(self):
        sm = SessionStateMachine(
            initial_state=SessionState.DISCONNECTED
        )
        sm.transition(SessionState.RECONNECTING)
        assert sm.state == SessionState.RECONNECTING

    def test_valid_reconnecting_to_reconnected(self):
        sm = SessionStateMachine(
            initial_state=SessionState.RECONNECTING
        )
        sm.transition(SessionState.RECONNECTED)
        assert sm.state == SessionState.RECONNECTED

    def test_valid_reconnecting_to_suspended(self):
        sm = SessionStateMachine(
            initial_state=SessionState.RECONNECTING
        )
        sm.transition(SessionState.SUSPENDED)
        assert sm.state == SessionState.SUSPENDED

    def test_valid_suspended_to_reconnecting(self):
        sm = SessionStateMachine(
            initial_state=SessionState.SUSPENDED
        )
        sm.transition(SessionState.RECONNECTING)
        assert sm.state == SessionState.RECONNECTING

    def test_valid_suspended_to_failed(self):
        sm = SessionStateMachine(
            initial_state=SessionState.SUSPENDED
        )
        sm.transition(SessionState.FAILED, reason="max retries")
        assert sm.state == SessionState.FAILED

    def test_valid_reconnected_to_connected(self):
        sm = SessionStateMachine(
            initial_state=SessionState.RECONNECTED
        )
        sm.transition(SessionState.CONNECTED)
        assert sm.state == SessionState.CONNECTED

    def test_invalid_connected_to_failed(self):
        sm = SessionStateMachine()
        with pytest.raises(ValueError, match="invalid"):
            sm.transition(SessionState.FAILED)
        assert sm.state == SessionState.CONNECTED

    def test_invalid_disconnected_to_connected(self):
        sm = SessionStateMachine(
            initial_state=SessionState.DISCONNECTED
        )
        with pytest.raises(ValueError):
            sm.transition(SessionState.CONNECTED)
        assert sm.state == SessionState.DISCONNECTED

    def test_invalid_failed_to_connected(self):
        sm = SessionStateMachine(
            initial_state=SessionState.FAILED
        )
        with pytest.raises(ValueError):
            sm.transition(SessionState.CONNECTED)
        assert sm.state == SessionState.FAILED

    def test_invalid_connected_to_reconnecting(self):
        sm = SessionStateMachine()
        with pytest.raises(ValueError):
            sm.transition(SessionState.RECONNECTING)

    def test_invalid_reconnected_to_failed(self):
        sm = SessionStateMachine(
            initial_state=SessionState.RECONNECTED
        )
        with pytest.raises(ValueError):
            sm.transition(SessionState.FAILED)

    def test_self_transition_rejected(self):
        sm = SessionStateMachine()
        with pytest.raises(ValueError):
            sm.transition(SessionState.CONNECTED)

    def test_event_emitted_on_transition(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.UNSTABLE, reason="high latency")

        events = sm.events
        assert len(events) == 1
        assert events[0].from_state == SessionState.CONNECTED
        assert events[0].to_state == SessionState.UNSTABLE
        assert events[0].reason == "high latency"

    def test_multiple_events(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.UNSTABLE)
        sm.transition(SessionState.DISCONNECTED)
        sm.transition(SessionState.RECONNECTING)

        events = sm.events
        assert len(events) == 3
        assert events[0].to_state == SessionState.UNSTABLE
        assert events[1].to_state == SessionState.DISCONNECTED
        assert events[2].to_state == SessionState.RECONNECTING

    def test_full_reconnection_cycle(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.UNSTABLE)
        sm.transition(SessionState.DISCONNECTED)
        sm.transition(SessionState.RECONNECTING)
        sm.transition(SessionState.RECONNECTED)
        sm.transition(SessionState.CONNECTED)
        assert sm.state == SessionState.CONNECTED

    def test_suspended_retry_cycle(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.DISCONNECTED)
        sm.transition(SessionState.RECONNECTING)
        sm.transition(SessionState.SUSPENDED)
        sm.transition(SessionState.RECONNECTING)
        sm.transition(SessionState.SUSPENDED)
        sm.transition(SessionState.FAILED, reason="max retries")
        assert sm.state == SessionState.FAILED

    def test_is_valid_transition_exhaustive(self):
        valid = [
            (SessionState.CONNECTED, SessionState.UNSTABLE),
            (SessionState.CONNECTED, SessionState.DISCONNECTED),
            (SessionState.UNSTABLE, SessionState.DISCONNECTED),
            (SessionState.UNSTABLE, SessionState.CONNECTED),
            (SessionState.DISCONNECTED, SessionState.RECONNECTING),
            (SessionState.RECONNECTING, SessionState.RECONNECTED),
            (SessionState.RECONNECTING, SessionState.SUSPENDED),
            (SessionState.SUSPENDED, SessionState.RECONNECTING),
            (SessionState.SUSPENDED, SessionState.FAILED),
            (SessionState.RECONNECTED, SessionState.CONNECTED),
        ]
        for from_s, to_s in valid:
            assert SessionStateMachine.is_valid_transition(
                from_s, to_s
            ), f"expected valid: {from_s.name} -> {to_s.name}"

        invalid = [
            (SessionState.CONNECTED, SessionState.FAILED),
            (SessionState.CONNECTED, SessionState.RECONNECTING),
            (SessionState.CONNECTED, SessionState.RECONNECTED),
            (SessionState.CONNECTED, SessionState.SUSPENDED),
            (SessionState.DISCONNECTED, SessionState.CONNECTED),
            (SessionState.DISCONNECTED, SessionState.FAILED),
            (SessionState.RECONNECTING, SessionState.CONNECTED),
            (SessionState.RECONNECTING, SessionState.FAILED),
            (SessionState.RECONNECTED, SessionState.FAILED),
            (SessionState.RECONNECTED, SessionState.DISCONNECTED),
            (SessionState.FAILED, SessionState.CONNECTED),
            (SessionState.FAILED, SessionState.RECONNECTING),
        ]
        for from_s, to_s in invalid:
            assert not SessionStateMachine.is_valid_transition(
                from_s, to_s
            ), f"expected invalid: {from_s.name} -> {to_s.name}"


class TestSession:
    def test_create(self):
        kp = IdentityKeypair.generate()
        pid = kp.peer_id().as_bytes()
        session = Session(peer_id=pid)
        assert session.peer_id == pid
        assert session.is_connected
        assert len(session.session_id) == 16

    def test_expiry(self):
        kp = IdentityKeypair.generate()
        session = Session(
            peer_id=kp.peer_id().as_bytes(),
            config=SessionConfig(expiry_secs=60),
        )
        assert not session.is_expired()
        assert session.is_expired(
            now=time.time() + 61
        )

    @pytest.mark.asyncio
    async def test_send_when_connected(self):
        kp = IdentityKeypair.generate()
        session = Session(peer_id=kp.peer_id().as_bytes())
        await session.send("chat", b"hello")

    @pytest.mark.asyncio
    async def test_send_when_disconnected_raises(self):
        kp = IdentityKeypair.generate()
        session = Session(peer_id=kp.peer_id().as_bytes())
        session.state_machine.transition(
            SessionState.DISCONNECTED
        )
        with pytest.raises(ConnectionError, match="not connected"):
            await session.send("chat", b"hello")

    @pytest.mark.asyncio
    async def test_deliver_and_receive(self):
        kp = IdentityKeypair.generate()
        session = Session(peer_id=kp.peer_id().as_bytes())
        session._deliver("chat", b"world")
        channel, data = await asyncio.wait_for(
            session.receive(), timeout=1.0
        )
        assert channel == "chat"
        assert data == b"world"

    @pytest.mark.asyncio
    async def test_close(self):
        kp = IdentityKeypair.generate()
        session = Session(peer_id=kp.peer_id().as_bytes())
        await session.close()
        assert session.state == SessionState.DISCONNECTED


class TestChannelValidation:
    def test_valid_names(self):
        validate_channel_name("my-channel")
        validate_channel_name("data")
        validate_channel_name("chat_room_1")

    def test_reserved_prefix_rejected(self):
        with pytest.raises(ValueError, match="reserved"):
            validate_channel_name("__cairn_forward")
        with pytest.raises(ValueError, match="reserved"):
            validate_channel_name("__cairn_custom")
        with pytest.raises(ValueError, match="reserved"):
            validate_channel_name("__cairn_")

    def test_empty_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            validate_channel_name("")

    def test_reserved_constants(self):
        assert RESERVED_CHANNEL_PREFIX == "__cairn_"
        assert CHANNEL_FORWARD == "__cairn_forward"
        assert CHANNEL_FORWARD.startswith(RESERVED_CHANNEL_PREFIX)


class TestChannel:
    def test_new_is_opening(self):
        ch = Channel("test", 1)
        assert ch.state == ChannelState.OPENING
        assert ch.name == "test"
        assert ch.stream_id == 1
        assert not ch.is_open

    def test_accept(self):
        ch = Channel("test", 1)
        ch.accept()
        assert ch.state == ChannelState.OPEN
        assert ch.is_open

    def test_reject(self):
        ch = Channel("test", 1)
        ch.reject()
        assert ch.state == ChannelState.REJECTED
        assert not ch.is_open

    def test_close_from_open(self):
        ch = Channel("test", 1)
        ch.accept()
        ch.close()
        assert ch.state == ChannelState.CLOSED
        assert not ch.is_open

    def test_close_from_opening(self):
        ch = Channel("test", 1)
        ch.close()
        assert ch.state == ChannelState.CLOSED

    def test_double_accept_rejected(self):
        ch = Channel("test", 1)
        ch.accept()
        with pytest.raises(ValueError):
            ch.accept()

    def test_accept_after_reject_rejected(self):
        ch = Channel("test", 1)
        ch.reject()
        with pytest.raises(ValueError):
            ch.accept()

    def test_double_close_rejected(self):
        ch = Channel("test", 1)
        ch.close()
        with pytest.raises(ValueError):
            ch.close()

    def test_with_metadata(self):
        ch = Channel("test", 1, metadata=b"\xCA\xFE")
        assert ch.metadata == b"\xCA\xFE"


class TestChannelInit:
    def test_cbor_roundtrip(self):
        init = ChannelInit(channel_name="my-channel")
        data = init.to_cbor()
        decoded = ChannelInit.from_cbor(data)
        assert decoded.channel_name == "my-channel"
        assert decoded.metadata is None

    def test_cbor_roundtrip_with_metadata(self):
        init = ChannelInit(
            channel_name="data-stream",
            metadata=b"\x01\x02\x03",
        )
        data = init.to_cbor()
        decoded = ChannelInit.from_cbor(data)
        assert decoded.channel_name == "data-stream"
        assert decoded.metadata == b"\x01\x02\x03"

    def test_decode_invalid(self):
        with pytest.raises(Exception):
            ChannelInit.from_cbor(bytes([0xFF, 0xFF]))


class TestChannelManager:
    def test_open_channel(self):
        mgr = ChannelManager()
        init = mgr.open_channel("chat", 1)
        assert init.channel_name == "chat"
        assert init.metadata is None
        assert mgr.channel_count == 1
        ch = mgr.get_channel(1)
        assert ch is not None
        assert ch.state == ChannelState.OPENING

    def test_open_reserved_rejected(self):
        mgr = ChannelManager()
        with pytest.raises(ValueError, match="reserved"):
            mgr.open_channel("__cairn_forward", 1)
        assert mgr.channel_count == 0

    def test_open_duplicate_stream_rejected(self):
        mgr = ChannelManager()
        mgr.open_channel("chat", 1)
        with pytest.raises(ValueError, match="already"):
            mgr.open_channel("other", 1)

    def test_handle_channel_init(self):
        mgr = ChannelManager()
        init = ChannelInit(
            channel_name="remote", metadata=b"\xAB"
        )
        mgr.handle_channel_init(5, init)
        assert mgr.channel_count == 1
        ch = mgr.get_channel(5)
        assert ch is not None
        assert ch.name == "remote"
        assert ch.state == ChannelState.OPENING

    def test_accept_channel(self):
        mgr = ChannelManager()
        init = ChannelInit(channel_name="ch")
        mgr.handle_channel_init(1, init)
        mgr.accept_channel(1)
        ch = mgr.get_channel(1)
        assert ch.state == ChannelState.OPEN

    def test_reject_channel(self):
        mgr = ChannelManager()
        init = ChannelInit(channel_name="ch")
        mgr.handle_channel_init(1, init)
        mgr.reject_channel(1)
        ch = mgr.get_channel(1)
        assert ch.state == ChannelState.REJECTED

    def test_close_channel(self):
        mgr = ChannelManager()
        init = ChannelInit(channel_name="ch")
        mgr.handle_channel_init(1, init)
        mgr.accept_channel(1)
        mgr.close_channel(1)
        ch = mgr.get_channel(1)
        assert ch.state == ChannelState.CLOSED

    def test_multiple_channels(self):
        mgr = ChannelManager()
        mgr.open_channel("ch1", 1)
        mgr.open_channel("ch2", 2)
        mgr.open_channel("ch3", 3)
        assert mgr.channel_count == 3
        assert mgr.get_channel(1).name == "ch1"
        assert mgr.get_channel(2).name == "ch2"
        assert mgr.get_channel(3).name == "ch3"
        assert mgr.get_channel(4) is None

    def test_open_with_metadata(self):
        mgr = ChannelManager()
        init = mgr.open_channel("meta", 1, metadata=b"\x01\x02")
        assert init.metadata == b"\x01\x02"
        ch = mgr.get_channel(1)
        assert ch.metadata == b"\x01\x02"

    def test_unknown_stream_raises(self):
        mgr = ChannelManager()
        with pytest.raises(ValueError, match="no channel"):
            mgr.accept_channel(99)
        with pytest.raises(ValueError, match="no channel"):
            mgr.reject_channel(99)
        with pytest.raises(ValueError, match="no channel"):
            mgr.close_channel(99)
