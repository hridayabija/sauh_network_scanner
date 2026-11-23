"""MTProxy transports + unauthenticated req_pq_multi, without Telegram clients.

Wire references: core.telegram.org/mtproto/mtproto-transports and
9seconds/mtg mtglib/{obfuscation,internal/tls/fake}; see docs/mtproxy.md.
"""

import asyncio
from datetime import datetime, timezone
import errno
import hashlib
import hmac
import ipaddress
import secrets
import socket
import ssl
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from kauliki_network_scanner.checks.core.mtproxy import MTProxySettings
from kauliki_network_scanner.checks.domain.mtproxy import (
    CHECKER_VERSION,
    DCObservation,
    ProxyObservation,
    ProxySecret,
    ProxySpec,
)


class ProtocolError(ValueError):
    pass


class MTProxyCheckerError(RuntimeError):
    """Local resource failure, not evidence about the proxy endpoint."""


def local_resource_error(error):
    return isinstance(error, OSError) and error.errno in {
        errno.EMFILE,
        errno.ENFILE,
        errno.ENOMEM,
        errno.ENOBUFS,
        errno.EADDRNOTAVAIL,
    }


def client_hello(secret: ProxySecret) -> tuple[bytes, bytes, bytes]:
    # OpenSSL builds a real TLS 1.3 ClientHello with SNI, key share and session ID.
    # Only its random is replaced; the SSL engine is not used after this point.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    connection = context.wrap_bio(incoming, outgoing, server_hostname=secret.sni)
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = bytearray(outgoing.read())
    if len(hello) < 76 or hello[:3] != b"\x16\x03\x01" or hello[5] != 1:
        raise ProtocolError("unsupported OpenSSL ClientHello")
    hello[11:43] = bytes(32)
    digest = bytearray(hmac.digest(secret.key, hello, "sha256"))
    stamp = struct.pack("<I", int(time.time()))
    for index in range(4):
        digest[28 + index] ^= stamp[index]
    hello[11:43] = digest
    return bytes(hello), bytes(digest), bytes(hello[44 : 44 + hello[43]])


async def read_tls_record(reader):
    header = await reader.readexactly(5)
    length = int.from_bytes(header[3:5], "big")
    if header[1:3] != b"\x03\x03" or not 0 < length <= 18432:
        raise ProtocolError("invalid TLS record")
    return header + await reader.readexactly(length)


async def authenticate_tls(reader, writer, secret):
    hello, random, session_id = client_hello(secret)
    writer.write(hello)
    await writer.drain()
    server = await read_tls_record(reader)
    if len(server) < 44 or server[0] != 0x16 or server[5] != 2:
        raise ProtocolError("not a TLS ServerHello")
    if (
        int.from_bytes(server[6:9], "big") != len(server) - 9
        or server[9:11] != b"\x03\x03"
    ):
        raise ProtocolError("invalid ServerHello length/version")
    if server[43] != len(session_id) or server[44 : 44 + len(session_id)] != session_id:
        raise ProtocolError("ServerHello session mismatch")
    ccs = await read_tls_record(reader)
    if ccs != b"\x14\x03\x03\x00\x01\x01":
        raise ProtocolError("missing TLS ChangeCipherSpec")
    noise = await read_tls_record(reader)
    if noise[0] != 0x17:
        raise ProtocolError("missing TLS handshake application data")
    packet = bytearray(server + ccs + noise)
    actual = bytes(packet[11:43])
    packet[11:43] = bytes(32)
    if not hmac.compare_digest(
        actual, hmac.digest(secret.key, random + packet, "sha256")
    ):
        raise ProtocolError("FakeTLS HMAC mismatch (wrong secret or fallback website)")
    writer.write(b"\x14\x03\x03\x00\x01\x01")
    await writer.drain()


def obfuscated_header(secret: ProxySecret, dc_id: int):
    while True:
        header = bytearray(secrets.token_bytes(64))
        if (
            header[0] != 0xEF
            and header[:4]
            not in (
                b"HEAD",
                b"POST",
                b"GET ",
                b"OPTI",
                b"\x16\x03\x01\x02",
                b"\xdd" * 4,
                b"\xee" * 4,
            )
            and header[4:8] != bytes(4)
        ):
            break
    header[56:60] = bytes([0xEE if secret.kind == "normal" else 0xDD]) * 4
    header[60:62] = struct.pack("<h", dc_id)
    reverse = header[8:56][::-1]
    tx = Cipher(
        algorithms.AES(hashlib.sha256(header[8:40] + secret.key).digest()),
        modes.CTR(bytes(header[40:56])),
    ).encryptor()
    rx = Cipher(
        algorithms.AES(hashlib.sha256(reverse[:32] + secret.key).digest()),
        modes.CTR(bytes(reverse[32:48])),
    ).decryptor()
    encrypted = tx.update(bytes(header))  # Consume all 64 CTR bytes, not just the tail.
    header[56:64] = encrypted[56:64]
    return bytes(header), tx, rx


class Transport:
    def __init__(self, reader, writer, secret, dc_id):
        self.reader, self.writer, self.secret = reader, writer, secret
        self.header, self.tx, self.rx = obfuscated_header(secret, dc_id)
        self.buffer = bytearray()

    async def write_wire(self, data):
        if self.secret.kind == "faketls":
            for offset in range(0, len(data), 16384):
                part = data[offset : offset + 16384]
                self.writer.write(b"\x17\x03\x03" + struct.pack(">H", len(part)) + part)
        else:
            self.writer.write(data)
        await self.writer.drain()

    async def read_wire(self, length):
        if self.secret.kind != "faketls":
            return await self.reader.readexactly(length)
        while len(self.buffer) < length:
            record = await read_tls_record(self.reader)
            if record[0] != 0x17:
                raise ProtocolError("unexpected record after FakeTLS handshake")
            self.buffer.extend(record[5:])
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    async def send(self, payload):
        padding = (
            secrets.token_bytes(secrets.randbelow(16))
            if self.secret.kind != "normal"
            else b""
        )
        framed = struct.pack("<I", len(payload) + len(padding)) + payload + padding
        await self.write_wire(self.tx.update(framed))

    async def receive(self):
        length = struct.unpack("<I", self.rx.update(await self.read_wire(4)))[0]
        if not 20 <= length <= 65536:
            raise ProtocolError("invalid MTProto frame length or transport error")
        return self.rx.update(await self.read_wire(length))


def req_pq(nonce, previous_id=0):
    message_id = max(
        (time.time_ns() * (1 << 32) // 1_000_000_000) & ~3, previous_id + 4
    )
    body = struct.pack("<I", 0xBE7E8EF1) + nonce
    return bytes(8) + struct.pack("<QI", message_id, len(body)) + body, message_id


def validate_res_pq(packet: bytes, nonce: bytes, padded: bool):
    if len(packet) < 76 or packet[:8] != bytes(8):
        raise ProtocolError("invalid unencrypted MTProto envelope")
    message_id, length = struct.unpack_from("<QI", packet, 8)
    padding = len(packet) - 20 - length
    # The unencrypted MTProto envelope can ALSO carry random padding. It is
    # separate from padded-intermediate's 0–15 trailing bytes. Real DC resPQ
    # responses commonly carry dozens/hundreds of extra bytes. Parse exactly
    # message_data_length and keep a bounded allowance for both padding layers.
    if length < 56 or length % 4 or not 0 <= padding <= 1024 + (15 if padded else 0):
        raise ProtocolError("invalid resPQ body length")
    if message_id % 4 not in {1, 3} or abs((message_id >> 32) - time.time()) > 300:
        raise ProtocolError("invalid server message ID/time")
    body = packet[20 : 20 + length]
    if body[:4] != struct.pack("<I", 0x05162463) or body[4:20] != nonce:
        raise ProtocolError("resPQ constructor/nonce mismatch")
    # pq:bytes (normally 8 bytes), followed by Vector<long> RSA fingerprints.
    pq_length = body[36]
    if not 1 <= pq_length <= 8:
        raise ProtocolError("invalid resPQ pq")
    position = 36 + ((1 + pq_length + 3) // 4) * 4
    if position + 8 > len(body):
        raise ProtocolError("truncated resPQ fingerprint vector")
    tag, count = struct.unpack_from("<II", body, position)
    if (
        tag != 0x1CB5C415
        or not 1 <= count <= 64
        or position + 8 + count * 8 != len(body)
    ):
        raise ProtocolError("invalid resPQ fingerprint vector")


async def resolve_public(host: str, port: int):
    addresses = await asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    )
    result = []
    for family, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if ip.is_global and (family, address[0]) not in result:
            result.append((family, address[0]))
    if not result:
        raise ProtocolError("DNS has no public IP addresses")
    return result


async def connect(addresses, port, timeout_seconds):
    last_error = OSError("no resolved addresses")
    # All addresses share one outer connect deadline; prefer IPv4 but try IPv6 too.
    for family, address in sorted(
        addresses, key=lambda item: item[0] != socket.AF_INET
    ):
        try:
            async with asyncio.timeout(timeout_seconds / len(addresses)):
                return await asyncio.open_connection(address, port, family=family)
        except (OSError, TimeoutError) as error:
            last_error = error
    raise last_error


async def check_proxy(
    spec: ProxySpec,
    config: MTProxySettings,
    geoip=None,
    *,
    claim_ip=None,
    preferred_ip=None,
    health_only=False,
) -> ProxyObservation | None:
    profile = (
        config.model_copy(
            update={
                "samples": 1,
                "sample_delay_seconds": 0,
                "connect_timeout_seconds": min(2.5, config.connect_timeout_seconds),
                "probe_timeout_seconds": min(3, config.probe_timeout_seconds),
            }
        )
        if health_only
        else config
    )
    result = ProxyObservation(
        checker_version=CHECKER_VERSION,
        validation_key=config.validation_key,
        health_validation_key=config.health_validation_key,
        samples=profile.samples,
        check_kind="health" if health_only else "full",
        dcs=[DCObservation(dc_id=dc) for dc in config.dc_ids],
    )
    begun = time.monotonic()
    try:
        async with asyncio.timeout(
            config.health_timeout_seconds
            if health_only
            else config.check_timeout_seconds
        ):
            result = await _check_proxy(
                spec,
                profile,
                result,
                geoip,
                claim_ip=claim_ip,
                preferred_ip=preferred_ip,
                health_only=health_only,
            )
    except TimeoutError:
        for dc in result.dcs:
            if not (
                dc.handshake_ok
                and len(dc.rtt_ms) == result.samples
                and dc.error is None
            ):
                dc.error = dc.error or "check: overall deadline exceeded"
    if result is not None:
        result.duration_ms = (time.monotonic() - begun) * 1000
        result.checked_at = datetime.now(timezone.utc)
    return result


async def _check_proxy(
    spec,
    config,
    result,
    geoip=None,
    *,
    claim_ip=None,
    preferred_ip=None,
    health_only=False,
):
    start = time.monotonic()
    secret = ProxySecret.parse(spec.secret)
    try:
        async with asyncio.timeout(config.connect_timeout_seconds):
            addresses = await resolve_public(spec.host, spec.port)
        result.dns_ms = (time.monotonic() - start) * 1000
    except (OSError, TimeoutError, ValueError) as error:
        if local_resource_error(error):
            raise MTProxyCheckerError("local resources exhausted during DNS") from error
        for dc in result.dcs:
            dc.error = f"dns: {type(error).__name__}: {error}"[:300]
        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    address = sorted(
        addresses, key=lambda item: (item[1] != preferred_ip, item[0] != socket.AF_INET)
    )[0]
    if claim_ip is not None:
        if not claim_ip(str(ipaddress.ip_address(address[1]))):
            return None
        # Pin the claimed address for every DC: a second DNS resolution or
        # unclaimed fallback address must not bypass the per-pass IP exclusion.
    addresses = [address]  # All DCs and the exported link refer to one tested IP.

    for index, dc in enumerate(result.dcs):
        dc.ip = sorted(addresses, key=lambda item: item[0] != socket.AF_INET)[0][1]
        writer = None
        phase = "tcp"
        begun = time.monotonic()
        try:
            async with asyncio.timeout(config.connect_timeout_seconds):
                reader, writer = await connect(
                    addresses, spec.port, config.connect_timeout_seconds
                )
            dc.tcp_ms = (time.monotonic() - begun) * 1000
            dc.ip = writer.get_extra_info("peername")[0]
            phase = "handshake"
            handshake_start = time.monotonic()
            async with asyncio.timeout(config.probe_timeout_seconds):
                if secret.kind == "faketls":
                    # This authenticates the endpoint before selecting any DC.
                    # Do not spend the whole multi-request budget on a silent site.
                    async with asyncio.timeout(config.connect_timeout_seconds):
                        await authenticate_tls(reader, writer, secret)
                    dc.handshake_ok = True
                    dc.handshake_ms = (time.monotonic() - handshake_start) * 1000
                transport = Transport(reader, writer, secret, dc.dc_id)
                await transport.write_wire(transport.header)
                phase = "req_pq_multi"
                previous_id = 0
                for sample in range(config.samples):
                    if sample:
                        await asyncio.sleep(config.sample_delay_seconds)
                    nonce = secrets.token_bytes(16)
                    packet, previous_id = req_pq(nonce, previous_id)
                    sent = time.monotonic()
                    await transport.send(packet)
                    validate_res_pq(
                        await transport.receive(), nonce, secret.kind != "normal"
                    )
                    dc.rtt_ms.append((time.monotonic() - sent) * 1000)
                    if sample == 0:
                        dc.first_response_ms = (time.monotonic() - begun) * 1000
                        if secret.kind != "faketls":
                            # Obfuscated2 has no standalone acknowledgement: only
                            # the valid response proves that its handshake succeeded.
                            dc.handshake_ms = (
                                time.monotonic() - handshake_start
                            ) * 1000
                            dc.handshake_ok = True
        except (
            OSError,
            TimeoutError,
            ValueError,
            asyncio.IncompleteReadError,
        ) as error:
            if local_resource_error(error):
                raise MTProxyCheckerError(
                    "local resources exhausted during the MTProxy check"
                ) from error
            dc.error = f"{phase}: {type(error).__name__}: {error}"[:300]
            if health_only:
                for pending in result.dcs[index + 1 :]:
                    pending.ip = address[1]
                    pending.error = "health: skipped after a failed DC"
                break
            if index == 0 and dc.tcp_ms is None:
                # Every DC uses the SAME proxy socket. Reconnecting to a closed
                # port five times gives no further DC reachability information.
                for pending in result.dcs[1:]:
                    pending.error = "tcp: skipped after endpoint connection failure"
                break
            if (
                phase == "handshake"
                and secret.kind == "faketls"
                and not dc.handshake_ok
            ):
                # Timeouts/EOF also happen before selecting a DC. Repeating this
                # identical handshake for all five DCs wastes 5 × the timeout.
                for pending in result.dcs[index + 1 :]:
                    pending.error = (
                        "handshake: skipped after endpoint authentication failure"
                    )
                break
        finally:
            if writer is not None:
                writer.close()
                try:
                    async with asyncio.timeout(1):
                        await writer.wait_closed()
                except (TimeoutError, OSError):
                    pass
    if geoip and result.ip:
        result.country_code = geoip.country(result.ip)
    result.duration_ms = (time.monotonic() - start) * 1000
    return result
