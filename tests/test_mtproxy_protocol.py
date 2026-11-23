"""Independent local MTProxy peer: real TCP, AES streams and fragmented TLS records.

No accounts, public proxies or Telegram DCs are contacted by these tests.
"""

import asyncio
import hashlib
import hmac
import os
from pathlib import Path
import socket
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from kauliki_network_scanner.checks.core.mtproxy import MTProxySettings
from kauliki_network_scanner.checks.domain.mtproxy import ProxySecret, ProxySpec
from kauliki_network_scanner.checks.services.mtproxy_check import check_many
from kauliki_network_scanner.checks.mtproxy.protocol import (
    ProtocolError,
    check_proxy,
    client_hello,
    req_pq,
    validate_res_pq,
)


KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def server_response(nonce):
    body = (
        struct.pack("<I", 0x05162463)
        + nonce
        + os.urandom(16)
        + b"\x08"
        + b"\x01" * 8
        + bytes(3)
        + struct.pack("<IIQ", 0x1CB5C415, 1, 0xC3B42B026CE86B21)
    )
    return bytes(8) + struct.pack("<QI", (int(time.time()) << 32) | 1, len(body)) + body


class EncodingTests(unittest.TestCase):
    def test_clienthello_has_authenticated_time_and_real_sni(self):
        secret = ProxySecret.parse("ee" + KEY.hex() + b"example.org".hex())
        hello, random, session = client_hello(secret)
        self.assertEqual(len(session), 32)
        self.assertIn(b"example.org", hello)
        self.assertEqual(int.from_bytes(hello[3:5], "big"), len(hello) - 5)
        expected = hmac.new(
            KEY, hello[:11] + bytes(32) + hello[43:], hashlib.sha256
        ).digest()
        self.assertEqual(random[:28], expected[:28])
        timestamp = int.from_bytes(
            bytes(a ^ b for a, b in zip(random[-4:], expected[-4:])), "little"
        )
        self.assertLess(abs(timestamp - time.time()), 2)

    def test_nonce_structure_replay_and_length_checks(self):
        nonce = bytes(range(16))
        packet = server_response(nonce)
        for padding in (0, 16, 96, 512, 1024):
            validate_res_pq(packet + bytes(padding), nonce, False)
        for padding in (0, 15, 58, 106, 1039):
            validate_res_pq(packet + bytes(padding), nonce, True)
        with self.assertRaises(ProtocolError):
            validate_res_pq(packet + bytes(1025), nonce, False)
        for broken in (
            packet[:20],
            packet + bytes(1040),
            packet[:20] + bytes(4) + packet[24:],
            packet[:28] + bytes(16) + packet[44:],
        ):
            with self.assertRaises(ProtocolError):
                validate_res_pq(broken, nonce, True)
        request, first = req_pq(nonce)
        _, second = req_pq(nonce, first)
        self.assertGreater(second, first)
        self.assertEqual(first % 4, 0)
        self.assertEqual(request[20:24], bytes.fromhex("f18e7ebe"))


class ProtocolPeerTests(unittest.IsolatedAsyncioTestCase):
    async def test_many_domains_for_one_ip_open_only_one_proxy_and_save_one_result(
        self,
    ):
        self.mode = "faketls"
        secret = "ee" + KEY.hex() + b"example.org".hex()
        specs = [
            ProxySpec.make(f"alias{index}.example.org", self.port, secret)
            for index in range(40)
        ]
        config = MTProxySettings(
            concurrency=10,
            samples=1,
            sample_delay_seconds=0,
            dc_ids=[2],
            connect_timeout_seconds=0.2,
            probe_timeout_seconds=0.2,
        )
        saved = []

        async def save(spec, result):
            saved.append((spec, result))

        self.assertEqual(await check_many(specs, config, save), 1)
        self.assertEqual(self.connections, 1)
        self.assertEqual(len(saved), 1)
        self.assertTrue(saved[0][1].working)
        # IP claims apply to one pass; the working-only pass must check it again.
        self.assertEqual(await check_many([specs[0]], config, save), 1)
        self.assertEqual(self.connections, 2)

    async def asyncSetUp(self):
        self.mode = "normal"
        self.fault = None
        self.peers = set()
        self.errors = []
        self.dc_ids = []
        self.connections = 0
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        self.resolver = patch(
            "kauliki_network_scanner.checks.mtproxy.protocol.resolve_public",
            return_value=[(socket.AF_INET, "127.0.0.1")],
        )
        self.resolver.start()
        self.addCleanup(self.resolver.stop)

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        for task in list(self.peers):
            task.cancel()
        if self.peers:
            await asyncio.gather(*self.peers, return_exceptions=True)
        self.assertEqual(self.errors, [])

    async def handle(self, reader, writer):
        self.connections += 1
        task = asyncio.current_task()
        self.peers.add(task)
        try:
            await self.exchange(reader, writer)
        except (OSError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        except Exception as error:
            self.errors.append(error)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            self.peers.discard(task)

    async def exchange(self, reader, writer):
        tls = self.mode == "faketls"
        if self.fault == "silent":
            await reader.read()
            return

        async def tls_read():
            header = await reader.readexactly(5)
            return header, await reader.readexactly(int.from_bytes(header[3:], "big"))

        if tls:
            head, body = await tls_read()
            client = head + body
            digest = hmac.new(
                KEY, client[:11] + bytes(32) + client[43:], hashlib.sha256
            ).digest()
            self.assertEqual(client[11:39], digest[:28])
            self.assertIn(b"example.org", client)
            session = client[44 : 44 + client[43]]
            payload = (
                b"\x03\x03"
                + bytes(32)
                + bytes([len(session)])
                + session
                + bytes.fromhex("1301000000")
            )
            handshake = b"\x02" + len(payload).to_bytes(3, "big") + payload
            reply = bytearray(
                b"\x16\x03\x03"
                + len(handshake).to_bytes(2, "big")
                + handshake
                + b"\x14\x03\x03\x00\x01\x01\x17\x03\x03\x00\x20"
                + os.urandom(32)
            )
            reply[11:43] = hmac.new(KEY, client[11:43] + reply, hashlib.sha256).digest()
            if self.fault == "fallback":
                reply[11] ^= 1
            # Force fragmentation across record and HMAC boundaries.
            writer.write(reply[:13])
            await writer.drain()
            await asyncio.sleep(0.001)
            writer.write(reply[13:])
            await writer.drain()
            ccs = await reader.readexactly(6)
            self.assertEqual(ccs, b"\x14\x03\x03\x00\x01\x01")

        buffered = bytearray()

        async def read_wire(size):
            if not tls:
                return await reader.readexactly(size)
            while len(buffered) < size:
                header, body = await tls_read()
                self.assertEqual(header[:3], b"\x17\x03\x03")
                buffered.extend(body)
            data = bytes(buffered[:size])
            del buffered[:size]
            return data

        header = await read_wire(64)
        reverse = header[8:56][::-1]
        incoming = Cipher(
            algorithms.AES(hashlib.sha256(header[8:40] + KEY).digest()),
            modes.CTR(header[40:56]),
        ).decryptor()
        outgoing = Cipher(
            algorithms.AES(hashlib.sha256(reverse[:32] + KEY).digest()),
            modes.CTR(reverse[32:48]),
        ).encryptor()
        decoded = incoming.update(header)
        if self.fault == "wrong-secret":
            return
        self.assertEqual(
            decoded[56:60], bytes([0xEE if self.mode == "normal" else 0xDD]) * 4
        )
        dc_id = int.from_bytes(decoded[60:62], "little")
        self.dc_ids.append(dc_id)
        for sample in range(3):
            length = int.from_bytes(incoming.update(await read_wire(4)), "little")
            request = incoming.update(await read_wire(length))
            self.assertEqual(request[:8], bytes(8))
            self.assertEqual(request[20:24], bytes.fromhex("f18e7ebe"))
            nonce = request[24:40]
            if self.fault == "nonce":
                nonce = bytes(16)
            response = server_response(nonce)
            # MTProto-level padding is independent of the transport padding.
            response += os.urandom((0, 96, 512)[sample])
            if self.mode != "normal":
                response += os.urandom(7)
            if self.fault == "huge":
                encrypted = outgoing.update(struct.pack("<I", 0x7FFFFFFF))
            else:
                encrypted = outgoing.update(struct.pack("<I", len(response)) + response)
            if tls:
                for part in (encrypted[:2], encrypted[2:7], encrypted[7:]):
                    writer.write(b"\x17\x03\x03" + len(part).to_bytes(2, "big") + part)
            else:
                writer.write(encrypted)
            await writer.drain()

    async def probe(self, *, key=KEY, dcs=None, geoip=None, sources_proxy=None):
        prefix = {"normal": "", "secure": "dd", "faketls": "ee"}[self.mode]
        secret = (
            prefix
            + key.hex()
            + (b"example.org".hex() if self.mode == "faketls" else "")
        )
        spec = ProxySpec.make("test.example.org", self.port, secret)
        config = MTProxySettings(
            samples=3,
            sample_delay_seconds=0,
            dc_ids=dcs or [2],
            connect_timeout_seconds=0.2,
            probe_timeout_seconds=0.2,
            sources_proxy=sources_proxy,
        )
        return await check_proxy(spec, config, geoip)

    async def test_sources_proxy_is_never_contacted_during_mtproxy_validation(self):
        contacts = []

        async def unexpected_proxy(reader, writer):
            contacts.append(True)
            writer.close()
            await writer.wait_closed()

        proxy = await asyncio.start_server(unexpected_proxy, "127.0.0.1", 0)
        try:
            port = proxy.sockets[0].getsockname()[1]
            for mode in ("normal", "secure", "faketls"):
                with self.subTest(mode=mode):
                    self.mode = mode
                    result = await self.probe(
                        dcs=[1, 2, 3, 4, 5],
                        sources_proxy=f"socks5h://harvest-user:harvest-password@127.0.0.1:{port}",
                    )
                    self.assertTrue(result.working, result.model_dump())
            self.assertEqual(contacts, [])
        finally:
            proxy.close()
            await proxy.wait_closed()

    async def test_all_transports_verify_multiple_dcs_and_measure_every_phase(self):
        for mode in ("normal", "secure", "faketls"):
            self.mode = mode
            result = await self.probe(dcs=[1, 2, 3, 4, 5])
            self.assertTrue(result.working, result.model_dump())
            for dc in result.dcs:
                self.assertEqual(len(dc.rtt_ms), 3)
                self.assertTrue(dc.handshake_ok)
                self.assertGreaterEqual(dc.tcp_ms, 0)
                self.assertGreaterEqual(dc.handshake_ms, 0)
                self.assertGreater(dc.first_response_ms, dc.tcp_ms)
        self.assertEqual(self.dc_ids, [1, 2, 3, 4, 5] * 3)

    async def test_health_authenticates_all_dcs_with_one_response_each(self):
        self.mode = "faketls"
        spec = ProxySpec.make(
            "test.example.org", self.port, "ee" + KEY.hex() + b"example.org".hex()
        )
        config = MTProxySettings(
            samples=3,
            dc_ids=[1, 2, 3, 4, 5],
            connect_timeout_seconds=0.2,
            probe_timeout_seconds=0.2,
        )
        result = await check_proxy(spec, config, health_only=True)
        self.assertTrue(result.working, result.model_dump())
        self.assertTrue(result.matches_health(config))
        self.assertFalse(result.matches_policy(config))
        self.assertEqual((result.check_kind, result.samples), ("health", 1))
        self.assertEqual(self.dc_ids, [1, 2, 3, 4, 5])
        self.assertEqual([len(dc.rtt_ms) for dc in result.dcs], [1] * 5)

    async def test_preferred_ip_is_pinned_for_all_dcs(self):
        self.mode = "normal"
        spec = ProxySpec.make("test.example.org", self.port, KEY.hex())
        config = MTProxySettings(
            samples=1,
            dc_ids=[1, 2, 3, 4, 5],
            connect_timeout_seconds=0.2,
            probe_timeout_seconds=0.2,
        )
        with patch(
            "kauliki_network_scanner.checks.mtproxy.protocol.resolve_public",
            return_value=[(socket.AF_INET, "127.0.0.2"), (socket.AF_INET, "127.0.0.1")],
        ):
            result = await check_proxy(spec, config, preferred_ip="127.0.0.1")
        self.assertTrue(result.working, result.model_dump())
        self.assertEqual({dc.ip for dc in result.dcs}, {"127.0.0.1"})

    async def test_open_port_silent_server_is_not_working(self):
        self.fault = "silent"
        result = await self.probe()
        self.assertIsNotNone(result.dcs[0].tcp_ms)
        self.assertFalse(result.working)
        self.assertFalse(result.dcs[0].handshake_ok)

    async def test_silent_faketls_endpoint_is_not_retried_for_every_dc(self):
        self.mode, self.fault = "faketls", "silent"
        result = await self.probe(dcs=[1, 2, 3, 4, 5])
        self.assertFalse(result.working)
        self.assertEqual(self.connections, 1)
        self.assertIn("handshake: TimeoutError", result.dcs[0].error)
        self.assertTrue(all("skipped" in dc.error for dc in result.dcs[1:]))
        self.assertEqual(result.checker_version, 4)

    async def test_faketls_uses_connect_deadline_instead_of_full_probe_budget(self):
        self.mode, self.fault = "faketls", "silent"
        spec = ProxySpec.make(
            "test.example.org", self.port, "ee" + KEY.hex() + b"example.org".hex()
        )
        config = MTProxySettings(
            dc_ids=[2], connect_timeout_seconds=0.03, probe_timeout_seconds=3
        )
        result = await asyncio.wait_for(check_proxy(spec, config), timeout=0.5)
        self.assertFalse(result.working)
        self.assertIn("handshake: TimeoutError", result.dcs[0].error)

    async def test_fallback_site_is_rejected_by_server_hmac(self):
        self.mode, self.fault = "faketls", "fallback"
        result = await self.probe()
        self.assertFalse(result.working)
        self.assertIn("HMAC mismatch", result.dcs[0].error)

    async def test_wrong_secret_nonce_and_unbounded_frame_fail_closed(self):
        self.fault = "wrong-secret"
        self.assertFalse((await self.probe(key=bytes(16))).working)
        for fault in ("nonce", "huge"):
            self.fault = fault
            self.assertFalse((await self.probe()).working)

    async def test_dns_failure_is_saved_for_every_dc_without_a_socket(self):
        with patch(
            "kauliki_network_scanner.checks.mtproxy.protocol.resolve_public",
            side_effect=OSError("NXDOMAIN"),
        ):
            result = await self.probe(dcs=[1, 2, 3, 4, 5])
        self.assertFalse(result.working)
        self.assertTrue(all(dc.error.startswith("dns:") for dc in result.dcs))
        self.assertEqual(self.dc_ids, [])


if __name__ == "__main__":
    unittest.main()
