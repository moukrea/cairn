"""Channel multiplexing over sessions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

import cbor2

RESERVED_CHANNEL_PREFIX: str = "__cairn_"
CHANNEL_FORWARD: str = "__cairn_forward"
CHANNEL_INIT_TYPE: int = 0x0303


def validate_channel_name(name: str) -> None:
    """Validate that a channel name is not reserved.

    Raises ValueError if the name is empty or uses the reserved prefix.
    """
    if not name:
        raise ValueError("channel name must not be empty")
    if name.startswith(RESERVED_CHANNEL_PREFIX):
        raise ValueError(
            f"channel name '{name}' uses reserved prefix "
            f"'{RESERVED_CHANNEL_PREFIX}'"
        )


class ChannelState(Enum):
    """Channel lifecycle states."""

    OPENING = auto()
    OPEN = auto()
    REJECTED = auto()
    CLOSED = auto()


class Channel:
    """A named channel multiplexed over a session stream."""

    def __init__(
        self,
        name: str,
        stream_id: int,
        metadata: bytes | None = None,
    ) -> None:
        self.name = name
        self.stream_id = stream_id
        self.state = ChannelState.OPENING
        self.metadata = metadata

    @property
    def is_open(self) -> bool:
        return self.state == ChannelState.OPEN

    def accept(self) -> None:
        """Transition to Open state."""
        if self.state != ChannelState.OPENING:
            raise ValueError(
                f"cannot accept channel '{self.name}' "
                f"in state {self.state.name}"
            )
        self.state = ChannelState.OPEN

    def reject(self) -> None:
        """Transition to Rejected state."""
        if self.state != ChannelState.OPENING:
            raise ValueError(
                f"cannot reject channel '{self.name}' "
                f"in state {self.state.name}"
            )
        self.state = ChannelState.REJECTED

    def close(self) -> None:
        """Transition to Closed state."""
        if self.state == ChannelState.CLOSED:
            raise ValueError(
                f"channel '{self.name}' is already closed"
            )
        self.state = ChannelState.CLOSED


@dataclass
class ChannelInit:
    """First message sent on a newly opened stream."""

    channel_name: str
    metadata: bytes | None = None

    def to_cbor(self) -> bytes:
        """Encode to CBOR."""
        m: dict[str, object] = {
            "channel_name": self.channel_name
        }
        if self.metadata is not None:
            m["metadata"] = self.metadata
        return cbor2.dumps(m)

    @classmethod
    def from_cbor(cls, data: bytes) -> ChannelInit:
        """Decode from CBOR."""
        m = cbor2.loads(data)
        return cls(
            channel_name=m["channel_name"],
            metadata=m.get("metadata"),
        )


class ChannelManager:
    """Manages channels within a session."""

    def __init__(self) -> None:
        self._channels: dict[int, Channel] = {}

    def open_channel(
        self,
        name: str,
        stream_id: int,
        metadata: bytes | None = None,
    ) -> ChannelInit:
        """Open a new channel on a given stream.

        Returns the ChannelInit payload to send.
        """
        validate_channel_name(name)
        if stream_id in self._channels:
            raise ValueError(
                f"stream {stream_id} already has a channel"
            )

        channel = Channel(name, stream_id, metadata)
        self._channels[stream_id] = channel
        return ChannelInit(
            channel_name=name, metadata=metadata
        )

    def handle_channel_init(
        self, stream_id: int, init: ChannelInit
    ) -> None:
        """Handle an incoming ChannelInit from a remote peer."""
        if stream_id in self._channels:
            raise ValueError(
                f"stream {stream_id} already has a channel"
            )
        channel = Channel(
            init.channel_name, stream_id, init.metadata
        )
        self._channels[stream_id] = channel

    def accept_channel(self, stream_id: int) -> None:
        """Accept an incoming channel."""
        channel = self._get_channel(stream_id)
        channel.accept()

    def reject_channel(self, stream_id: int) -> None:
        """Reject an incoming channel."""
        channel = self._get_channel(stream_id)
        channel.reject()

    def close_channel(self, stream_id: int) -> None:
        """Close a channel."""
        channel = self._get_channel(stream_id)
        channel.close()

    def get_channel(self, stream_id: int) -> Channel | None:
        """Get a channel by stream ID."""
        return self._channels.get(stream_id)

    @property
    def channel_count(self) -> int:
        return len(self._channels)

    def _get_channel(self, stream_id: int) -> Channel:
        channel = self._channels.get(stream_id)
        if channel is None:
            raise ValueError(
                f"no channel on stream {stream_id}"
            )
        return channel
