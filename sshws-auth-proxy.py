#!/usr/bin/env python3
"""Authenticated HTTP/SOCKS4/SOCKS5 forward proxy for authorized users."""
from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import json
import logging
import os
import struct
from pathlib import Path
from urllib.parse import urlsplit

HOST = os.environ.get("SSHWS_PROXY_HOST", "0.0.0.0")
PORT = int(os.environ.get("SSHWS_PROXY_PORT", "1080"))
CREDENTIALS = Path(os.environ.get("SSHWS_PROXY_CREDENTIALS", "/etc/ssh-ws/proxy-users.json"))
MAX_HEADER = 16384
LOG = logging.getLogger("sshws-auth-proxy")


def credentials() -> dict[str, str]:
    try:
        data = json.loads(CREDENTIALS.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.get("users", {}).items() if str(k) and str(v)}
    except (OSError, ValueError, TypeError):
        return {}


def authorized(username: str, password: str) -> bool:
    expected = credentials().get(username)
    return expected is not None and expected == password


async def read_until_headers(reader: asyncio.StreamReader) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) <= MAX_HEADER:
        chunk = await reader.read(1024)
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > MAX_HEADER:
        raise ValueError("headers too large")
    return bytes(data)


async def tunnel(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, upstream_reader: asyncio.StreamReader, upstream_writer: asyncio.StreamWriter) -> None:
    async def pipe(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
        try:
            while chunk := await source.read(65536):
                destination.write(chunk)
                await destination.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                destination.write_eof()
            except (AttributeError, OSError):
                pass

    tasks = [asyncio.create_task(pipe(reader, upstream_writer)), asyncio.create_task(pipe(upstream_reader, writer))]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def host_port(value: str, default_port: int = 80) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("[") and "]" in value:
        host, _, port = value[1:].partition("]")
        return host, int(port[1:] if port.startswith(":") else default_port)
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, default_port


async def open_target(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)


async def socks5(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
    methods = await reader.readexactly((await reader.readexactly(1))[0])
    if 2 not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        return False
    writer.write(b"\x05\x02")
    await writer.drain()
    version = await reader.readexactly(1)
    if version != b"\x01":
        return False
    length = (await reader.readexactly(1))[0]
    raw = await reader.readexactly(length + 1)
    username = raw[:length].decode("utf-8", "replace")
    plen = raw[length]
    password = (await reader.readexactly(plen)).decode("utf-8", "replace")
    if not authorized(username, password):
        writer.write(b"\x01\x01")
        await writer.drain()
        return False
    writer.write(b"\x01\x00")
    await writer.drain()
    ver, command, _reserved, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
    if ver != 5 or command != 1:
        writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        return False
    if atyp == 1:
        host = str(ipaddress.ip_address(await reader.readexactly(4)))
    elif atyp == 3:
        host = (await reader.readexactly((await reader.readexactly(1))[0])).decode("idna")
    elif atyp == 4:
        host = str(ipaddress.ip_address(await reader.readexactly(16)))
    else:
        return False
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    try:
        upstream_reader, upstream_writer = await open_target(host, port)
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        await tunnel(reader, writer, upstream_reader, upstream_writer)
        upstream_writer.close()
        await upstream_writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        return False


async def socks4(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
    command = (await reader.readexactly(1))[0]
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    raw_ip = await reader.readexactly(4)
    userid = bytearray()
    while (byte := await reader.readexactly(1)) != b"\x00":
        userid.extend(byte)
    host = str(ipaddress.ip_address(raw_ip))
    if raw_ip[:3] == b"\x00\x00\x00" and raw_ip[3] != 0:
        domain = bytearray()
        while (byte := await reader.readexactly(1)) != b"\x00":
            domain.extend(byte)
        host = domain.decode("idna")
    if command != 1 or not authorized(userid.decode("utf-8", "replace"), ""):
        writer.write(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        return False
    try:
        upstream_reader, upstream_writer = await open_target(host, port)
        writer.write(b"\x00\x5a\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        await tunnel(reader, writer, upstream_reader, upstream_writer)
        upstream_writer.close()
        await upstream_writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        writer.write(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        return False


async def http_proxy(initial: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
    try:
        head = initial.decode("latin-1")
        lines = head.split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower().strip()] = value.strip()
        auth = headers.get("proxy-authorization", "")
        if not auth.lower().startswith("basic "):
            raise PermissionError
        username, password = base64.b64decode(auth[6:], validate=True).decode("utf-8").split(":", 1)
        if not authorized(username, password):
            raise PermissionError
        if method.upper() == "CONNECT":
            host, port = host_port(target, 443)
            upstream_reader, upstream_writer = await open_target(host, port)
            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: SSHWS-Auth-Proxy\r\n\r\n")
            await writer.drain()
            await tunnel(reader, writer, upstream_reader, upstream_writer)
            upstream_writer.close()
            await upstream_writer.wait_closed()
            return True
        parsed = urlsplit(target)
        host_header = headers.get("host", "")
        host, port = host_port(parsed.netloc or host_header, 443 if parsed.scheme == "https" else 80)
        upstream_reader, upstream_writer = await open_target(host, port)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        forwarded = [f"{method} {path} {version}"]
        for key, value in headers.items():
            if key not in {"proxy-authorization", "proxy-connection"}:
                forwarded.append(f"{key}: {value}")
        forwarded.append("")
        forwarded.append("")
        upstream_writer.write("\r\n".join(forwarded).encode("latin-1") + await reader.read())
        await upstream_writer.drain()
        while chunk := await upstream_reader.read(65536):
            writer.write(chunk)
            await writer.drain()
        upstream_writer.close()
        await upstream_writer.wait_closed()
        return True
    except (PermissionError, binascii.Error, UnicodeError, ValueError, IndexError, OSError, asyncio.TimeoutError):
        writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=SSHWS\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return False


async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        first = await asyncio.wait_for(reader.readexactly(1), timeout=15)
        if first == b"\x05":
            await socks5(reader, writer)
        elif first == b"\x04":
            await socks4(reader, writer)
        else:
            await http_proxy(first + await read_until_headers(reader), reader, writer)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ValueError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = await asyncio.start_server(client, HOST, PORT, limit=MAX_HEADER)
    LOG.info("authenticated HTTP/SOCKS4/SOCKS5 proxy listening on %s:%d", HOST, PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
