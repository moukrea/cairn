"""WebSocket transport implementation (priority 6: WebSocket/TLS on port 443).

Uses the ``websockets`` library for async WebSocket I/O with
length-prefixed binary framing over WebSocket binary messages.
"""

from __future__ import annotations

import struct

from cairn.transport.chain import DEFAULT_TIMEOUT, Transport


class WebSocketTransport(Transport):
    """WebSocket transport using the ``websockets`` library.

    Messages are sent as WebSocket binary frames with the same
    4-byte big-endian length prefix used by the TCP transport,
    ensuring wire-level compatibility.
    """

    def __init__(self) -> None:
        self._ws: object | None = None

    async def connect(
        self, addr: str, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        """Connect to a WebSocket endpoint.

        addr should be a ws:// or wss:// URL.
        """
        import asyncio

        import websockets

        self._ws = await asyncio.wait_for(
            websockets.connect(addr),
            timeout=timeout,
        )

    async def send(self, data: bytes) -> None:
        if self._ws is None:
            raise ConnectionError("not connected")
        # Length-prefixed framing inside WebSocket binary message
        header = struct.pack(">I", len(data))
        await self._ws.send(header + data)  # type: ignore[union-attr]

    async def receive(self) -> bytes:
        if self._ws is None:
            raise ConnectionError("not connected")
        msg = await self._ws.recv()  # type: ignore[union-attr]
        if isinstance(msg, str):
            msg = msg.encode()
        if len(msg) < 4:
            raise ValueError("WebSocket message too short for framing")
        length = struct.unpack(">I", msg[:4])[0]
        return msg[4 : 4 + length]

    async def close(self) -> None:
        if self._ws is not None:
            try:
                await self._ws.close()  # type: ignore[union-attr]
            except Exception:
                pass
            self._ws = None
