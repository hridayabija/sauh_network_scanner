"""Inspect the negotiated TLS without replacing the client's browser fingerprint.

sing-box's uTLS presets can override min_version and cipher_suites. This private
SOCKS detour forwards ClientHello unchanged and gates ServerHello before the core
can accept it. Certificate/REALITY authentication remains the core's job.
"""

import asyncio
from contextlib import suppress
import ipaddress
import secrets

from sauh_network_scanner.checks.domain.vpn import TLSNegotiation


TLS12_CIPHERS = {
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}
TLS13_CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}
RETRY_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)
MAX_RECORD_BYTES = 18432
MAX_HELLO_BYTES = 131072


class TLSAuditError(ValueError):
    """Remote TLS is unacceptable; messages never contain credentials."""


class _RelayRejected(ValueError):
    """An unauthenticated or unexpected local SOCKS request."""


def server_hello(body, minimum_version):
    """Parse TLS 1.2/1.3 ServerHello, including supported_versions and HRR."""
    if len(body) < 38 or body[:2] != b"\x03\x03":
        raise TLSAuditError("invalid or obsolete TLS ServerHello")
    session_length = body[34]
    cursor = 35 + session_length
    if session_length > 32 or len(body) < cursor + 3:
        raise TLSAuditError("invalid TLS session ID")
    cipher_id = int.from_bytes(body[cursor : cursor + 2])
    if body[cursor + 2] != 0:
        raise TLSAuditError("TLS compression is forbidden")
    cursor += 3
    version, extensions = 0x0303, set()
    if len(body) != cursor:
        if (
            len(body) < cursor + 2
            or int.from_bytes(body[cursor : cursor + 2]) != len(body) - cursor - 2
        ):
            raise TLSAuditError("invalid TLS extensions")
        cursor += 2
        while cursor < len(body):
            if len(body) < cursor + 4:
                raise TLSAuditError("incomplete TLS extension")
            kind, size = (
                int.from_bytes(body[cursor : cursor + 2]),
                int.from_bytes(body[cursor + 2 : cursor + 4]),
            )
            cursor += 4
            if kind in extensions or len(body) < cursor + size:
                raise TLSAuditError("invalid or duplicate TLS extension")
            extensions.add(kind)
            if kind == 43:
                if size != 2:
                    raise TLSAuditError("invalid negotiated TLS version")
                version = int.from_bytes(body[cursor : cursor + size])
            cursor += size
    if version not in {0x0303, 0x0304} or version < minimum_version:
        raise TLSAuditError("negotiated TLS version is below the required minimum")
    cipher = (TLS13_CIPHERS if version == 0x0304 else TLS12_CIPHERS).get(cipher_id)
    if cipher is None:
        raise TLSAuditError("negotiated TLS cipher is not an allowed AEAD suite")
    retry = body[2:34] == RETRY_RANDOM
    if retry and version != 0x0304:
        raise TLSAuditError("invalid TLS HelloRetryRequest")
    return TLSNegotiation(
        version="1.3" if version == 0x0304 else "1.2", cipher=cipher
    ), retry


async def inspect_server_hello(reader, writer, minimum_version):
    """Buffer fragmented records until an acceptable ServerHello can be forwarded."""
    pending, handshake = bytearray(), bytearray()
    total_bytes, retry_negotiation = 0, None
    for _ in range(256):
        header = await reader.readexactly(5)
        size = int.from_bytes(header[3:5])
        if (
            header[1:3] not in {b"\x03\x01", b"\x03\x02", b"\x03\x03"}
            or not 0 < size <= MAX_RECORD_BYTES
        ):
            raise TLSAuditError("invalid TLS record before ServerHello")
        total_bytes += 5 + size
        if total_bytes > MAX_HELLO_BYTES:
            raise TLSAuditError("TLS ServerHello exceeds the size limit")
        payload = await reader.readexactly(size)
        pending.extend(header + payload)
        if header[0] == 20 and payload == b"\x01" and not handshake:
            continue  # TLS 1.3 compatibility ChangeCipherSpec.
        if header[0] == 21:
            raise TLSAuditError("TLS alert before ServerHello")
        if header[0] != 22:
            raise TLSAuditError("expected a plaintext TLS ServerHello")
        handshake.extend(payload)
        if len(handshake) < 4:
            continue
        hello_size = 4 + int.from_bytes(handshake[1:4])
        if handshake[0] != 2 or hello_size > MAX_HELLO_BYTES:
            raise TLSAuditError("invalid TLS ServerHello handshake")
        if len(handshake) < hello_size:
            continue
        negotiated, retry = server_hello(handshake[4:hello_size], minimum_version)
        if retry_negotiation is not None and (retry or negotiated != retry_negotiation):
            raise TLSAuditError("invalid final ServerHello after HelloRetryRequest")
        if retry and len(handshake) != hello_size:
            raise TLSAuditError("unexpected handshake after HelloRetryRequest")
        writer.write(pending)
        await writer.drain()
        if not retry:
            return negotiated
        retry_negotiation = negotiated
        pending.clear()
        handshake.clear()
    raise TLSAuditError("too many TLS records before ServerHello")


async def _copy(reader, writer):
    while block := await reader.read(65536):
        writer.write(block)
        await writer.drain()
    if writer.can_write_eof():
        writer.write_eof()
        await writer.drain()


async def _close(writer):
    writer.close()
    with suppress(OSError):
        await writer.wait_closed()


class TLSAuditRelay:
    """A short-lived loopback SOCKS5 server restricted to one pinned public IP."""

    def __init__(self, address, port, minimum_version, timeout):
        self.address = ipaddress.ip_address(address)
        if not self.address.is_global:
            raise ValueError("TLS audit requires a pinned public address")
        self.port, self.minimum_version, self.timeout = port, minimum_version, timeout
        self.username, self.password = secrets.token_hex(8), secrets.token_hex(24)
        self.server = None
        self.tasks, self.writers = set(), set()
        self.closed = False
        self.negotiations = {}
        self.error, self.local_error = None, None

    async def __aenter__(self):
        self.server = await asyncio.start_server(
            self._accept, "127.0.0.1", 0, limit=MAX_RECORD_BYTES * 2
        )
        return self

    async def __aexit__(self, *_):
        self.closed = True
        self.server.close()
        await self.server.wait_closed()
        for writer in tuple(self.writers):
            writer.close()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.writers.clear()
        self.tasks.clear()

    def outbound(self):
        return {
            "type": "socks",
            "tag": "tls-audit",
            "server": "127.0.0.1",
            "server_port": self.server.sockets[0].getsockname()[1],
            "version": "5",
            "username": self.username,
            "password": self.password,
        }

    async def open_upstream(self):
        # Production never resolves a SOCKS-supplied hostname or follows a redirect.
        return await asyncio.open_connection(str(self.address), self.port)

    def _accept(self, reader, writer):
        if self.closed or len(self.tasks) >= 16:
            writer.close()
            return
        task = asyncio.create_task(self._handle(reader, writer))
        self.writers.add(writer)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _authenticate(self, reader, writer):
        version, count = await reader.readexactly(2)
        if version != 5 or not count or 2 not in await reader.readexactly(count):
            writer.write(b"\x05\xff")
            await writer.drain()
            raise _RelayRejected()
        writer.write(b"\x05\x02")
        await writer.drain()
        version, size = await reader.readexactly(2)
        username = await reader.readexactly(size)
        password = await reader.readexactly((await reader.readexactly(1))[0])
        if (
            version != 1
            or not secrets.compare_digest(username, self.username.encode())
            or not secrets.compare_digest(password, self.password.encode())
        ):
            writer.write(b"\x01\x01")
            await writer.drain()
            raise _RelayRejected()
        writer.write(b"\x01\x00")
        await writer.drain()
        version, command, reserved, kind = await reader.readexactly(4)
        if (version, command, reserved) != (5, 1, 0) or kind not in {1, 4}:
            writer.write(b"\x05\x02\x00\x01" + b"\x00" * 6)
            await writer.drain()
            raise _RelayRejected()
        address = ipaddress.ip_address(await reader.readexactly(4 if kind == 1 else 16))
        port = int.from_bytes(await reader.readexactly(2))
        if address != self.address or port != self.port:
            writer.write(b"\x05\x02\x00\x01" + b"\x00" * 6)
            await writer.drain()
            raise _RelayRejected()

    async def _checked_copy(self, reader, writer):
        negotiated = await inspect_server_hello(reader, writer, self.minimum_version)
        self.negotiations[(negotiated.version, negotiated.cipher)] = negotiated
        await _copy(reader, writer)

    async def _handle(self, reader, writer):
        upstream, directions = None, []
        self.writers.add(writer)
        try:
            async with asyncio.timeout(self.timeout):
                await self._authenticate(reader, writer)
                remote_reader, upstream = await self.open_upstream()
                self.writers.add(upstream)
                writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
                await writer.drain()
                directions = [
                    asyncio.create_task(_copy(reader, upstream)),
                    asyncio.create_task(self._checked_copy(remote_reader, writer)),
                ]
                await asyncio.gather(*directions)
        except TLSAuditError as error:
            self.error = self.error or error
        except (_RelayRejected, OSError, TimeoutError, asyncio.IncompleteReadError):
            pass  # The real HTTPS probe will fail; local strangers never affect the rating.
        except Exception as error:
            self.local_error = self.local_error or error
        finally:
            for task in directions:
                task.cancel()
            await asyncio.gather(*directions, return_exceptions=True)
            for connection in (writer, upstream):
                if connection is not None:
                    self.writers.discard(connection)
                    await _close(connection)
