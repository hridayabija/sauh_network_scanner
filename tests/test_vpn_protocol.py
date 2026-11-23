"""Real local encrypted VPN servers; no public endpoints or production DB are used."""

import asyncio
import base64
from contextlib import asynccontextmanager, ExitStack
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import ipaddress
import gzip
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sauh_network_scanner.checks.core.vpn import VPNSettings
from sauh_network_scanner.checks.domain.vpn import PROTOCOL_LABELS, VPNSpec
from sauh_network_scanner.checks.vpn.core import (
    CoreError,
    CoreRunner,
    checker_config,
    terminate,
)
from sauh_network_scanner.checks.vpn.probe import check_vpn
from vpn_support import UUID, spec


CORE = Path(
    os.environ.get(
        "SINGBOX_TEST_BINARY",
        str(
            Path(__file__).resolve().parents[1]
            / "state/bin"
            / ("sing-box.exe" if os.name == "nt" else "sing-box")
        ),
    )
)


def ports(count):
    with ExitStack() as stack:
        reservations = [stack.enter_context(socket.socket()) for _ in range(count)]
        for item in reservations:
            item.bind(("127.0.0.1", 0))
        return [item.getsockname()[1] for item in reservations]


def certificates(directory, *, hostname="vpn.example.com"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VPN tests CA")])
    now = datetime.now(timezone.utc)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False),
            True,
        )
        .sign(key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False
        )
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
            True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(hostname),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = [
        Path(directory) / value for value in ("ca.pem", "cert.pem", "key.pem")
    ]
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


@unittest.skipUnless(
    CORE.is_file(), "install sing-box for real VPN protocol integration tests"
)
class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        loop = asyncio.get_running_loop()
        loop.slow_callback_duration = (
            1  # Local RSA fixture creation runs synchronously.
        )
        previous_handler = loop.get_exception_handler()

        def expected_tls_reset(current_loop, context):
            if isinstance(
                context.get("exception"), ConnectionResetError
            ) and "transport creation" in context.get("message", ""):
                return  # Negative REALITY tests deliberately abort the mask-site handshake.
            if previous_handler:
                previous_handler(current_loop, context)
            else:
                current_loop.default_exception_handler(context)

        loop.set_exception_handler(expected_tls_reset)
        self.addCleanup(loop.set_exception_handler, previous_handler)
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-protocol-test-")
        self.addCleanup(self.temp.cleanup)
        self.ca, cert, key = certificates(self.temp.name)
        self.trust = patch.dict(os.environ, {"SSL_CERT_FILE": str(self.ca)})
        self.trust.start()
        self.addCleanup(self.trust.stop)
        self.target_requests = []
        self.download_headers = []
        self.upload_received = []
        app = web.Application()

        async def probe(request):
            self.target_requests.append(request.path)
            if request.path == "/slow":
                await asyncio.sleep(2)
            bad = request.path == "/bad-probe" or (
                request.path == "/flaky" and self.target_requests.count("/flaky") == 1
            )
            return web.Response(status=200 if bad else 204)

        async def trace(request):
            self.target_requests.append(request.path)
            body = (
                b"ip=127.0.0.1\nloc=US\n"
                if request.path == "/invalid-trace"
                else b"ip=1.1.1.1\nloc=US\n"
            )
            # Cloudflare negotiates gzip when the client advertises it. Exercise
            # the real wire behavior rather than an always-uncompressed fixture.
            if "gzip" in request.headers.get("Accept-Encoding", "").lower():
                return web.Response(
                    body=gzip.compress(body), headers={"Content-Encoding": "gzip"}
                )
            return web.Response(body=body, content_type="text/plain")

        async def download(request):
            self.target_requests.append(request.path)
            self.download_headers.append(dict(request.headers))
            return web.Response(
                body=b"a" * (65536 if request.path == "/download" else 100)
            )

        async def upload(request):
            self.target_requests.append(request.path)
            received = 0
            async for block in request.content.iter_chunked(4096):
                received += len(block)
            self.upload_received.append(received)
            if request.path == "/upload-rejected":
                return web.Response(status=405)
            if request.path == "/upload-no-receipt":
                return web.Response()
            if request.path == "/upload-short-receipt":
                received -= 1
            if request.path == "/upload-stalled":
                await asyncio.sleep(2)
            return web.Response(headers={"cf-meta-upload-bytes": str(received)})

        app.router.add_get("/204", probe)
        app.router.add_get("/204-two", probe)
        app.router.add_get("/204-three", probe)
        app.router.add_get("/bad-probe", probe)
        app.router.add_get("/slow", probe)
        app.router.add_get("/flaky", probe)
        app.router.add_get("/trace", trace)
        app.router.add_get("/invalid-trace", trace)
        app.router.add_get("/download", download)
        app.router.add_get("/short", download)
        for path in (
            "/upload",
            "/upload-no-receipt",
            "/upload-short-receipt",
            "/upload-rejected",
            "/upload-stalled",
        ):
            app.router.add_post(path, upload)
        self.http = web.AppRunner(app, access_log=None, shutdown_timeout=1)
        await self.http.setup()
        self.addAsyncCleanup(self.http.cleanup)
        target = ports(1)[0]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        await web.TCPSite(self.http, "127.0.0.1", target, ssl_context=context).start()
        plain_target = ports(1)[0]
        await web.TCPSite(self.http, "127.0.0.1", plain_target).start()
        self.plain_download_url = f"http://127.0.0.1:{plain_target}/download"
        self.config = VPNSettings(
            core_path=str(CORE),
            samples=2,
            sample_delay_seconds=0,
            connect_timeout_seconds=1,
            probe_timeout_seconds=1,
            check_timeout_seconds=6,
            download_bytes=65536,
            probe_url=f"https://127.0.0.1:{target}/204",
            trace_url=f"https://127.0.0.1:{target}/trace",
            download_url=f"https://127.0.0.1:{target}/download",
            upload_bytes=65536,
            upload_url=f"https://127.0.0.1:{target}/upload",
            upload_timeout_seconds=1,
        )
        self.specs, inbounds = {}, []
        entry_ports = ports(16)
        for protocol, port in zip(PROTOCOL_LABELS, entry_ports):
            value = spec(protocol, port=port)
            self.specs[protocol] = value
            inbound = {
                "type": "shadowsocks" if protocol == "ss" else protocol,
                "listen": "127.0.0.1",
                "listen_port": port,
            }
            if protocol == "ss":
                inbound.update(
                    method=value.outbound["method"], password=value.outbound["password"]
                )
            elif protocol == "hysteria2":
                inbound["users"] = [{"password": value.outbound["password"]}]
            else:
                fields = (
                    ("uuid", "password")
                    if protocol == "tuic"
                    else ("password",)
                    if protocol == "trojan"
                    else ("uuid",)
                )
                inbound["users"] = [{field: value.outbound[field] for field in fields}]
            if protocol != "ss":
                inbound["tls"] = {
                    "enabled": True,
                    "certificate_path": str(cert),
                    "key_path": str(key),
                }
                if protocol in {"tuic", "hysteria2"}:
                    inbound["tls"].update(alpn=["h3"], min_version="1.3")
            inbounds.append(inbound)
        reality_key = x25519.X25519PrivateKey.generate()
        public = (
            base64.urlsafe_b64encode(reality_key.public_key().public_bytes_raw())
            .decode()
            .rstrip("=")
        )
        private = (
            base64.urlsafe_b64encode(reality_key.private_bytes_raw())
            .decode()
            .rstrip("=")
        )
        self.specs["reality"] = VPNSpec.from_uri(
            f"vless://{UUID}@vpn.example.com:{entry_ports[6]}?security=reality"
            f"&sni=vpn.example.com&pbk={public}&sid=1234&flow=xtls-rprx-vision"
        )
        inbounds.append(
            {
                "type": "vless",
                "listen": "127.0.0.1",
                "listen_port": entry_ports[6],
                "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": True,
                    "server_name": "vpn.example.com",
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": "127.0.0.1", "server_port": target},
                        "private_key": private,
                        "short_id": ["1234"],
                    },
                },
            }
        )
        self.specs["reality_ws"] = VPNSpec.from_uri(
            f"vless://{UUID}@vpn.example.com:{entry_ports[15]}?security=reality"
            f"&sni=vpn.example.com&pbk={public}&sid=1234&type=ws&host=vpn.example.com&path=%2Fws"
        )
        inbounds.append(
            {
                "type": "vless",
                "listen": "127.0.0.1",
                "listen_port": entry_ports[15],
                "users": [{"uuid": UUID}],
                "transport": self.specs["reality_ws"].outbound["transport"],
                "tls": {
                    "enabled": True,
                    "server_name": "vpn.example.com",
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": "127.0.0.1", "server_port": target},
                        "private_key": private,
                        "short_id": ["1234"],
                    },
                },
            }
        )
        self.weak_spec = spec("vless", port=entry_ports[7])
        inbounds.append(
            {
                "type": "vless",
                "listen": "127.0.0.1",
                "listen_port": entry_ports[7],
                "users": [{"uuid": UUID}],
                "tls": {
                    "enabled": True,
                    "certificate_path": str(cert),
                    "key_path": str(key),
                    "min_version": "1.2",
                    "max_version": "1.2",
                    "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"],
                },
            }
        )
        self.tls12_spec = spec("vless", port=entry_ports[8])
        self.tls12_specs = {"vless": self.tls12_spec}
        inbounds.append(
            {
                "type": "vless",
                "listen": "127.0.0.1",
                "listen_port": entry_ports[8],
                "users": [{"uuid": UUID}],
                "tls": {
                    "enabled": True,
                    "certificate_path": str(cert),
                    "key_path": str(key),
                    "min_version": "1.2",
                    "max_version": "1.2",
                    "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
                },
            }
        )
        for protocol, port in zip(("trojan", "vmess"), entry_ports[13:]):
            value = spec(protocol, port=port)
            self.tls12_specs[protocol] = value
            auth_field = "password" if protocol == "trojan" else "uuid"
            inbounds.append(
                {
                    "type": protocol,
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "users": [{auth_field: value.outbound[auth_field]}],
                    "tls": {
                        "enabled": True,
                        "certificate_path": str(cert),
                        "key_path": str(key),
                        "min_version": "1.2",
                        "max_version": "1.2",
                        "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
                    },
                }
            )
        self.specs["firefox"] = VPNSpec.from_uri(
            self.specs["vless"].uri.replace("fp=firefox", "fp=chrome")
        )
        for kind, port in zip(("ws", "grpc", "http", "httpupgrade"), entry_ports[9:]):
            params = (
                "serviceName=vpn-tests"
                if kind == "grpc"
                else "host=vpn.example.com&path=%2Fvpn"
            )
            value = VPNSpec.from_uri(
                f"vless://{UUID}@vpn.example.com:{port}?security=tls&type={kind}&{params}"
            )
            self.specs[f"vless_{kind}"] = value
            inbounds.append(
                {
                    "type": "vless",
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "users": [{"uuid": UUID}],
                    "tls": {
                        "enabled": True,
                        "certificate_path": str(cert),
                        "key_path": str(key),
                        "alpn": ["h2"] if kind in {"grpc", "http"} else ["http/1.1"],
                    },
                    "transport": value.outbound["transport"],
                }
            )
        path = Path(self.temp.name) / "server.json"
        path.write_text(
            json.dumps(
                {
                    "log": {"disabled": True},
                    "inbounds": inbounds,
                    "outbounds": [{"type": "direct", "tag": "direct"}],
                    "route": {"final": "direct"},
                }
            )
        )
        self.server = await asyncio.create_subprocess_exec(
            str(CORE),
            "run",
            "-c",
            str(path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        self.addAsyncCleanup(terminate, self.server)
        async with asyncio.timeout(5):
            while True:
                if self.server.returncode is not None:
                    self.fail((await self.server.stderr.read()).decode())
                try:
                    _, writer = await asyncio.open_connection(
                        "127.0.0.1", entry_ports[0]
                    )
                    writer.close()
                    await writer.wait_closed()
                    break
                except ConnectionRefusedError:
                    await asyncio.sleep(0.05)
        self.resolver = patch(
            "sauh_network_scanner.checks.vpn.probe.resolve_public",
            new=AsyncMock(return_value=[(socket.AF_INET, "8.8.8.8")]),
        )

        # The fixture maps public identities to its local VPN emulators.
        async def local_preflight(address, port, timeout):
            async with asyncio.timeout(timeout):
                _, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()

        self.preflight = patch(
            "sauh_network_scanner.checks.vpn.probe.tcp_preflight",
            new=local_preflight,
        )
        self.preflight.start()
        self.addCleanup(self.preflight.stop)

        # Only the fixture translates the public-looking identity into a local emulator.
        def local_config(value, address, port, settings, user, password):
            result = checker_config(
                value,
                address
                if value.protocol in {"vless", "vmess", "trojan"}
                else "127.0.0.1",
                port,
                settings,
                user,
                password,
            )
            secure = result["outbounds"][0].get("tls")
            if secure is not None and not secure.get("reality"):
                # Go on Windows/macOS may use the OS root store. Trust only
                # this synthetic fixture CA explicitly; verification stays on.
                secure["certificate_path"] = str(self.ca)
            return result

        self.local_route = patch(
            "sauh_network_scanner.checks.vpn.core.checker_config",
            side_effect=local_config,
        )

        async def local_upstream(relay):
            return await asyncio.open_connection("127.0.0.1", relay.port)

        self.audit_route = patch(
            "sauh_network_scanner.checks.vpn.tls_audit.TLSAuditRelay.open_upstream",
            new=local_upstream,
        )
        self.resolver.start()
        self.local_route.start()
        self.audit_route.start()
        self.addCleanup(self.resolver.stop)
        self.addCleanup(self.local_route.stop)
        self.addCleanup(self.audit_route.stop)
        self.core = CoreRunner(self.config)
        await self.core.prepare()

    async def test_all_protocols_and_reality_relay_authenticated_https_and_measure_throughput(
        self,
    ):
        for name, value in self.specs.items():
            with self.subTest(protocol=name):
                self.target_requests.clear()
                result = await check_vpn(value, self.config, self.core)
                self.assertTrue(result.working, result.error)
                self.assertEqual(
                    (result.exit_ip, result.country_code), ("1.1.1.1", "US")
                )
                self.assertEqual(result.download_bytes, 65536)
                self.assertGreater(result.download_mbps, 0)
                self.assertEqual(
                    (result.upload_bytes, result.upload_confirmed_bytes), (65536, 65536)
                )
                self.assertEqual(self.upload_received[-1], 65536)
                self.assertGreater(result.upload_mbps, 0)
                if value.protocol in {"vless", "vmess", "trojan"}:
                    self.assertTrue(result.tls_sessions)
                    self.assertTrue(
                        all(session.version == "1.3" for session in result.tls_sessions)
                    )
                self.assertEqual(
                    self.target_requests,
                    ["/204", "/204", "/trace", "/download", "/upload"],
                )

    async def test_health_uses_authenticated_tunnel_without_trace_or_transfer(self):
        for name in ("vless", "ss", "tuic"):
            with self.subTest(protocol=name):
                self.target_requests.clear()
                result = await check_vpn(
                    self.specs[name], self.config, self.core, health_only=True
                )
                self.assertTrue(result.working, result.error)
                self.assertEqual((result.check_kind, result.samples), ("health", 1))
                self.assertEqual(
                    result.health_validation_key, self.config.health_validation_key
                )
                self.assertFalse(result.download_ok or result.upload_ok)
                self.assertIsNone(result.exit_ip)
                self.assertEqual(self.target_requests, ["/204"])
        self.assertEqual(self.upload_received, [])
        self.target_requests.clear()
        config = self.config.model_copy(
            update={"probe_url": self.config.probe_url.replace("/204", "/bad-probe")}
        )
        result = await check_vpn(
            self.specs["vless"], config, self.core, health_only=True
        )
        self.assertFalse(result.working)
        self.assertEqual(self.target_requests, ["/bad-probe"])

    async def test_sources_proxy_is_never_contacted_during_vpn_validation(self):
        contacts = []

        async def unexpected_proxy(reader, writer):
            contacts.append(True)
            writer.close()
            await writer.wait_closed()

        proxy = await asyncio.start_server(unexpected_proxy, "127.0.0.1", 0)
        try:
            port = proxy.sockets[0].getsockname()[1]
            config = VPNSettings(
                **{
                    **self.config.model_dump(),
                    "sources_proxy": f"socks5h://harvest-user:harvest-password@127.0.0.1:{port}",
                }
            )
            core = CoreRunner(config)
            await core.prepare()
            for name in ("vless", "ss"):
                with self.subTest(protocol=name):
                    self.target_requests.clear()
                    result = await check_vpn(self.specs[name], config, core)
                    self.assertTrue(result.working, result.error)
                    self.assertEqual(
                        (result.download_bytes, result.upload_confirmed_bytes),
                        (65536, 65536),
                    )
                    self.assertEqual(
                        self.target_requests,
                        ["/204", "/204", "/trace", "/download", "/upload"],
                    )
            self.assertEqual(contacts, [])
        finally:
            proxy.close()
            await proxy.wait_closed()

    async def test_every_latency_endpoint_is_probed_before_bidirectional_transfer(self):
        urls = [
            self.config.probe_url,
            self.config.probe_url + "-two",
            self.config.probe_url + "-three",
        ]
        config = self.config.model_copy(update={"probe_url": urls})
        result = await check_vpn(self.specs["vless"], config, self.core)
        self.assertTrue(result.working, result.error)
        self.assertEqual([probe.url for probe in result.latency_probes], urls)
        self.assertTrue(all(len(probe.rtt_ms) == 2 for probe in result.latency_probes))
        self.assertEqual(len(result.rtt_ms), 6)
        self.assertEqual(
            result.first_response_ms,
            max(probe.first_response_ms for probe in result.latency_probes),
        )
        self.assertEqual(
            self.target_requests,
            [
                "/204",
                "/204",
                "/204-two",
                "/204-two",
                "/204-three",
                "/204-three",
                "/trace",
                "/download",
                "/upload",
            ],
        )

    async def test_one_unavailable_latency_endpoint_preserves_traffic_and_other_samples(
        self,
    ):
        for path in ("/bad-probe", "/slow"):
            with self.subTest(endpoint=path):
                self.target_requests.clear()
                bad_url = self.config.probe_url.replace("/204", path)
                config = self.config.model_copy(
                    update={"probe_url": [self.config.probe_url, bad_url]}
                )
                result = await check_vpn(self.specs["vless"], config, self.core)
                self.assertTrue(result.working)
                self.assertFalse(result.complete)
                self.assertTrue(result.error.startswith("probe:"), result.error)
                self.assertIsNotNone(result.latency_probes[-1].error)
                self.assertEqual(
                    self.target_requests,
                    ["/204", "/204", path, path, "/trace", "/download", "/upload"],
                )
                self.assertTrue(result.download_ok and result.upload_ok)

    async def test_failed_first_latency_sample_does_not_hide_later_success(self):
        urls = [
            self.config.probe_url.replace("/204", "/bad-probe"),
            self.config.probe_url.replace("/204", "/flaky"),
            self.config.probe_url,
        ]
        result = await check_vpn(
            self.specs["vless"],
            self.config.model_copy(update={"probe_url": urls}),
            self.core,
        )
        self.assertTrue(result.working, result.error)
        self.assertFalse(result.complete)
        self.assertEqual(
            [len(probe.rtt_ms) for probe in result.latency_probes], [0, 0, 2]
        )
        self.assertIsNotNone(result.first_response_ms)

    async def test_no_validated_204_never_starts_transfer(self):
        config = self.config.model_copy(
            update={"probe_url": self.config.probe_url.replace("/204", "/bad-probe")}
        )
        result = await check_vpn(self.specs["vless"], config, self.core)
        self.assertFalse(result.working or result.reachable)
        self.assertNotIn("/download", self.target_requests)
        self.assertNotIn("/upload", self.target_requests)

    async def test_light_retry_checks_other_urls_and_requires_full_transfer_when_response_appears(
        self,
    ):
        urls = [
            self.config.probe_url.replace("/204", "/bad-probe"),
            self.config.probe_url,
        ]
        config = self.config.model_copy(update={"probe_url": urls})
        result = await check_vpn(
            self.specs["vless"], config, self.core, quick_retry=True, attempt=1
        )
        self.assertTrue(result.working, result.error)
        self.assertEqual(
            self.target_requests,
            ["/bad-probe", "/204", "/204", "/trace", "/download", "/upload"],
        )
        self.assertEqual([len(probe.rtt_ms) for probe in result.latency_probes], [0, 2])

    async def test_preferred_and_alternate_ips_are_pinned_from_validated_dns_answers(
        self,
    ):
        self.resolver.stop()
        with patch(
            "sauh_network_scanner.checks.vpn.probe.resolve_public",
            new=AsyncMock(
                return_value=[(socket.AF_INET, "8.8.8.8"), (socket.AF_INET, "9.9.9.9")]
            ),
        ):
            first = await check_vpn(
                self.specs["vless"], self.config, self.core, preferred_ip="9.9.9.9"
            )
            second = await check_vpn(
                self.specs["vless"],
                self.config,
                self.core,
                preferred_ip="9.9.9.9",
                attempt=2,
            )
        self.assertTrue(first.working and second.working)
        self.assertEqual(
            (first.resolved_ip, second.resolved_ip), ("9.9.9.9", "8.8.8.8")
        )

    async def test_plain_http_download_uses_proxy_auth_without_exposing_it_to_origin(
        self,
    ):
        config = self.config.model_copy(
            update={"download_url": self.plain_download_url}
        )
        result = await check_vpn(self.specs["vless"], config, self.core)
        self.assertTrue(result.working, result.error)
        self.assertEqual(result.download_bytes, 65536)
        self.assertNotIn("Proxy-Authorization", self.download_headers[-1])
        self.assertNotIn("Authorization", self.download_headers[-1])

    async def test_successful_download_requires_confirmed_upload(self):
        for path, reason in (
            ("/upload-no-receipt", "upload receipt missing"),
            ("/upload-short-receipt", "incomplete upload receipt"),
            ("/upload-rejected", "upload returned HTTP 405"),
            ("/upload-stalled", "TimeoutError"),
        ):
            with self.subTest(endpoint=path):
                self.target_requests.clear()
                config = self.config.model_copy(
                    update={
                        "upload_url": self.config.upload_url.replace("/upload", path)
                    }
                )
                result = await check_vpn(self.specs["vless"], config, self.core)
                self.assertTrue(result.download_ok)
                self.assertFalse(result.working or result.upload_ok)
                self.assertIsNone(result.upload_mbps)
                self.assertTrue(result.error.startswith("upload:"), result.error)
                self.assertIn(reason, result.error)
                self.assertEqual(self.upload_received[-1], 65536)
                self.assertEqual(self.target_requests[-1], path)

    async def test_wrong_authentication_and_certificate_name_never_reach_probe(self):
        for value in (
            VPNSpec.from_uri(self.specs["vless"].uri.replace(UUID, "a" + UUID[1:])),
            VPNSpec.from_uri(
                self.specs["vless"].uri.replace(
                    "sni=vpn.example.com", "sni=wrong.example.com"
                )
            ),
            VPNSpec.from_uri(
                self.specs["firefox"].uri.replace(
                    "sni=vpn.example.com", "sni=wrong.example.com"
                )
            ),
        ):
            with self.subTest(identity=value.key):
                self.target_requests.clear()
                result = await check_vpn(value, self.config, self.core)
                self.assertFalse(result.working)
                self.assertEqual(self.target_requests, [])

    async def test_trace_endpoint_negotiating_gzip_does_not_reject_a_working_tunnel(
        self,
    ):
        result = await check_vpn(self.specs["vless"], self.config, self.core)
        self.assertTrue(result.working, result.error)
        self.assertEqual((result.exit_ip, result.country_code), ("1.1.1.1", "US"))
        self.assertEqual(result.download_bytes, self.config.download_bytes)
        self.assertEqual(
            self.target_requests, ["/204", "/204", "/trace", "/download", "/upload"]
        )

    async def test_invalid_exit_is_rejected_and_identifies_the_trace_phase(self):
        config = self.config.model_copy(
            update={
                "trace_url": self.config.trace_url.replace("/trace", "/invalid-trace")
            }
        )
        result = await check_vpn(self.specs["vless"], config, self.core)
        self.assertFalse(result.working)
        self.assertEqual(len(result.rtt_ms), self.config.samples)
        self.assertIn("trace: ProbeError: invalid exit trace", result.error)
        self.assertIn("/download", self.target_requests)
        self.assertTrue(result.download_ok and result.upload_ok)

    async def test_reality_fallback_https_server_is_not_a_working_vpn(self):
        wrong = (
            base64.urlsafe_b64encode(
                x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()
            )
            .decode()
            .rstrip("=")
        )
        for name in ("reality", "reality_ws"):
            with self.subTest(transport=name):
                value = self.specs[name]
                value = VPNSpec.from_uri(
                    value.uri.replace(
                        value.outbound["tls"]["reality"]["public_key"], wrong
                    )
                )
                result = await check_vpn(value, self.config, self.core)
                self.assertFalse(result.working)
                self.assertIsNone(result.exit_ip)

    async def test_server_offering_only_non_aead_tls_is_rejected(self):
        for value in (
            self.weak_spec,
            VPNSpec.from_uri(self.weak_spec.uri.replace("fp=firefox", "fp=chrome")),
        ):
            with self.subTest(fingerprint=value.outbound["tls"].get("utls")):
                self.target_requests.clear()
                result = await check_vpn(value, self.config, self.core)
                self.assertFalse(result.working)
                self.assertEqual(self.target_requests, [])
                if value.outbound["tls"].get("utls"):
                    self.assertIn("TLSAuditError", result.error)

    async def test_tls12_aead_is_allowed_with_firefox_for_vless_trojan_and_vmess(self):
        for protocol, value in self.tls12_specs.items():
            with self.subTest(protocol=protocol):
                self.assertEqual(
                    value.outbound["tls"]["utls"]["fingerprint"], "firefox"
                )
                result = await check_vpn(value, self.config, self.core)
                self.assertTrue(result.working, result.error)
                self.assertEqual(
                    [
                        (session.version, session.cipher)
                        for session in result.tls_sessions
                    ],
                    [("1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")],
                )
        # An explicitly stricter requirement is still enforced by the relay.
        outbound = {
            **self.tls12_spec.outbound,
            "tls": {**self.tls12_spec.outbound["tls"], "min_version": "1.3"},
        }
        self.target_requests.clear()
        result = await check_vpn(
            replace(self.tls12_spec, outbound=outbound), self.config, self.core
        )
        self.assertFalse(result.working)
        self.assertIn("TLSAuditError", result.error)
        self.assertTrue(result.safety_error)
        self.assertEqual(self.target_requests, [])

    async def test_successful_ping_with_partial_download_is_not_working(self):
        config = self.config.model_copy(
            update={
                "download_url": self.config.download_url.replace("/download", "/short")
            }
        )
        result = await check_vpn(self.specs["vless"], config, self.core)
        self.assertEqual(len(result.rtt_ms), 2)
        self.assertFalse(result.working or result.download_ok)
        self.assertIn("incomplete speed response", result.error)
        self.assertTrue(result.error.startswith("download:"))
        self.assertTrue(result.upload_ok)

    async def test_waiting_for_local_startup_is_inconclusive_and_remains_cancellable(
        self,
    ):
        self.core.startup_slots = asyncio.Semaphore(0)
        config = self.config.model_copy(update={"health_timeout_seconds": 0.1})
        with self.assertRaisesRegex(CoreError, "local sing-box startup"):
            await check_vpn(self.specs["vless"], config, self.core, health_only=True)
        self.assertEqual(self.target_requests, [])
        task = asyncio.create_task(
            check_vpn(self.specs["vless"], self.config, self.core, health_only=True)
        )
        await asyncio.sleep(0.02)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_local_core_failure_propagates_instead_of_recording_dead_nodes(self):
        with patch(
            "sauh_network_scanner.checks.vpn.core.checker_config",
            return_value={"outbounds": [{"type": "unknown-core-type"}]},
        ):
            with self.assertRaises(CoreError):
                await check_vpn(self.specs["vless"], self.config, self.core)

    async def test_core_exiting_during_request_is_an_infrastructure_failure(self):
        original = self.core.tunnel

        @asynccontextmanager
        async def tunnel(*args):
            async with original(*args) as value:

                async def stop_core():
                    await asyncio.sleep(0.05)
                    await terminate(value[2])

                stopper = asyncio.create_task(stop_core())
                try:
                    yield value
                finally:
                    await stopper

        self.core.tunnel = tunnel
        config = self.config.model_copy(
            update={"probe_url": self.config.probe_url.replace("/204", "/slow")}
        )
        with self.assertRaises(CoreError):
            await check_vpn(self.specs["vless"], config, self.core)

    async def test_cancellation_terminates_inflight_core_process(self):
        processes, audits, ready = [], [], asyncio.Event()
        original = self.core.tunnel

        @asynccontextmanager
        async def tunnel(*args):
            async with original(*args) as value:
                processes.append(value[2])
                audits.append(value[3])
                ready.set()
                yield value

        self.core.tunnel = tunnel
        config = self.config.model_copy(
            update={"probe_url": self.config.probe_url.replace("/204", "/slow")}
        )
        task = asyncio.create_task(check_vpn(self.specs["vless"], config, self.core))
        await ready.wait()
        await asyncio.sleep(0.05)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(processes)
        self.assertTrue(all(process.returncode is not None for process in processes))
        self.assertTrue(
            all(
                audit.closed and not audit.tasks and not audit.writers
                for audit in audits
            )
        )


if __name__ == "__main__":
    unittest.main()
