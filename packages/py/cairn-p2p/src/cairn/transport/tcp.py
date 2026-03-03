"""TCP transport implementation using asyncio."""

from __future__ import annotations

import asyncio
import struct

from cairn.transport.chain import DEFAULT_TIMEOUT, Transport


class TcpTransport(Transport):
    """TCP transport using asyncio streams.

    Messages are length-prefixed with a 4-byte big-endian header.
    """

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(
        self, addr: str, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        """Connect to host:port."""
        host, port_str = addr.rsplit(":", 1)
        port = int(port_str)
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

    async def send(self, data: bytes) -> None:
        if self._writer is None:
            raise ConnectionError("not connected")
        header = struct.pack(">I", len(data))
        self._writer.write(header + data)
        await self._writer.drain()

    async def receive(self) -> bytes:
        if self._reader is None:
            raise ConnectionError("not connected")
        header = await self._reader.readexactly(4)
        length = struct.unpack(">I", header)[0]
        return await self._reader.readexactly(length)

    async def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

    @staticmethod
    async def create_server(
        host: str,
        port: int,
        handler: object,
    ) -> asyncio.Server:
        """Create a TCP server (listener).

        handler should be an async callable(reader, writer).
        """
        return await asyncio.start_server(
            handler,  # type: ignore[arg-type]
            host,
            port,
        )
