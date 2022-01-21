#!/usr/bin/env python3
"""
A helper library in BearCTL tools. Provides a safer socket communication, where
each message is transmitted with its length. The api is async and is designed
in a way so you can replace asyncio's socket and client server functions with
ones from this library, and it would still work.

Author: Morj, d86leader@mail.com
License: GNU GPL, for more info: https://www.gnu.org/licenses/gpl-3.0.txt
"""

from asyncio import StreamReader, StreamWriter
from typing import Tuple, Awaitable
import asyncio
import struct
import sys


class LenStreamError(Exception):
    """Thrown by stream operations on exceptional cases"""
    pass

def _sum_bytes(x: int) -> int:
    if x < 0:
        raise LenStreamError("Summing bytes of negative number")
    s = 0
    while x > 0:
        s += x & 0xff
        x >>= 8
    return s

class LenStreamReader:
    """
    Wrapper around asyncio.StreamReader. You can obtain instances by using
    `start_server` or `open_connection`.
    """
    _reader: StreamReader

    def __init__(self, reader: StreamReader):
        self._reader = reader

    async def read(self) -> bytes:
        """Read next message from stream."""
        length = await self._read_length()
        return await self._reader.readexactly(length)

    def at_eof(self) -> bool:
        """Returns `True` if the buffer is empty and `write_eof` was called"""
        return self._reader.at_eof()

    async def _read_length(self) -> int:
        packed_len = await self._reader.readexactly(5)
        (length, check) = struct.unpack("<IB", packed_len)
        if check != _sum_bytes(length):
            raise LenStreamError("Bad byte sequence at message start")
        return length

class LenStreamWriter:
    """
    Wrapper around asyncio.StreamWriter. You can obtain instances by using
    start_server() or open_connection()
    """
    _writer: StreamWriter

    def __init__(self, writer: StreamWriter):
        self._writer = writer

    def write(self, data: bytes) -> None:
        """Write message to stream."""
        self._send_length(len(data))
        self._writer.write(data)

    async def drain(self) -> None:
        """
        Wait until it is appropriate to resume writing to stream.
        See asyncio docs for more info.
        """
        await self._writer.drain()

    def close(self) -> None:
        """Close the underlying stream."""
        self._writer.close()

    def write_eof(self) -> None:
        """Close the stream after the buffered data is flushed."""
        self._writer.write_eof()

    def _send_length(self, length: int) -> None:
        check = _sum_bytes(length)
        packed_len = struct.pack("<IB", length, check)
        self._writer.write(packed_len)


async def open_connection(*args, **kwargs
        ) -> Tuple[LenStreamReader, LenStreamWriter]:
    """
    Create a network connection and return a pair of `(reader, writer)`
    objects, which are instances of LenStreamReader and LenStreamWriter. The
    arguments are passed directly to `asyncio.open_connection`
    """
    base_reader, base_writer = await asyncio.open_connection(*args, **kwargs)
    return (LenStreamReader(base_reader), LenStreamWriter(base_writer))

async def start_server(callback, *args, **kwargs) -> asyncio.AbstractServer:
    """
    Start a socket server.

    The callback is called whenever a new client
    connection is established. It receives a `(reader, writer)` pair as two
    arguments, instances of LenStreamReader and LenStreamWriter classes. The
    callback should be a coroutine function. Other arguments are passed
    directly to `asyncio.start_server`.

    Return value is the same as `asyncio.start_server`.
    """
    async def base_callback(base_reader, base_writer):
        reader = LenStreamReader(base_reader)
        writer = LenStreamWriter(base_writer)
        await callback(reader, writer)
    return await asyncio.start_server(base_callback, *args, **kwargs)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"{sys.argv[0]} client/server port")
        sys.exit(1)
    loop = asyncio.get_event_loop()
    port = int(sys.argv[2])
    if sys.argv[1] == "client":
        async def client():
            reader, writer = await open_connection("localhost", port)
            writer.write(b"client sends his regads")
            print(await reader.read())
        loop.run_until_complete(client())
    elif sys.argv[1] == "server":
        async def handler(reader, writer):
            print(await reader.read())
            writer.write(b"hell yeah")
        async def server():
            s = await start_server(handler, "localhost", port)
            await s.wait_closed()
        loop.run_until_complete(server())
