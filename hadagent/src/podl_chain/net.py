from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional

from .packets import Packet


PacketHandler = Callable[[Packet, asyncio.StreamWriter], Awaitable[None]]

#  Small async TCP server for newline-delimited packet exchange
class AsyncNodeServer:

    def __init__(self, host: str, port: int, handler: PacketHandler) -> None:
        self.host = host
        self.port = port
        self.handler = handler
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break

                pkt = Packet.from_bytes(raw)
                await self.handler(pkt, writer)
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            
            print(f"[server] client error: {exc}")
        finally:
            writer.close()
            await writer.wait_closed()


async def send_packet(host: str, port: int, pkt: Packet) -> None:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(pkt.to_bytes())
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def send_packet_expect_one_response(host: str, port: int, pkt: Packet) -> Packet:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(pkt.to_bytes())
        await writer.drain()

        raw = await reader.readline()
        if not raw:
            raise RuntimeError("No response received from peer.")
        return Packet.from_bytes(raw)
    finally:
        writer.close()
        await writer.wait_closed()