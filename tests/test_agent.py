import asyncio
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from aiohttp import web
from aiohttp.test_utils import TestServer

from sauh_network_scanner.api import APIClient, APIError
from sauh_network_scanner.autostart import definition
from sauh_network_scanner.config import Settings
from sauh_network_scanner.runtime import Runtime
from sauh_network_scanner.storage import DeviceLock, Outbox


KEY = "synthetic-only-key-" + "A" * 40


class ConfigurationTests(unittest.TestCase):
    def test_api_proxy_is_optional_validated_and_redacted(self):
        self.assertIsNone(Settings().api_proxy)
        for scheme in ("http", "https", "socks4", "socks5", "socks5h"):
            with self.subTest(scheme=scheme):
                proxy = f"{scheme}://user:private-proxy-password@127.0.0.1:1080"
                settings = Settings(api_proxy=proxy)
                self.assertEqual(settings.api_proxy.get_secret_value(), proxy)
                self.assertNotIn("private-proxy-password", settings.model_dump_json())
        for invalid in (
            "ftp://proxy.example:1080",
            "http://proxy.example",
            "http://proxy.example:65536",
            "http://proxy.example:8080/api",
            "socks5://private-proxy-user@proxy.example:1080",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError) as error:
                Settings(api_proxy=invalid)
            self.assertNotIn(invalid, str(error.exception))

    def test_plain_http_and_embedded_credentials_are_rejected(self):
        for origin in (
            "http://example.com",
            "https://user:password@example.com",
            "https://api.example.com/path",
            "https://api.example.com?key=secret",
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                Settings(api_url=origin)

    def test_loopback_http_requires_explicit_test_mode(self):
        with self.assertRaises(ValueError):
            Settings(api_url="http://127.0.0.1:8000")
        self.assertTrue(
            Settings(api_url="http://127.0.0.1:8000", allow_http_loopback=True)
        )

    def test_harvest_and_database_settings_are_not_client_capabilities(self):
        for field in ("sources", "DATABASE_URL", "BOT_TOKEN", "ssh", "network_group"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                Settings.model_validate({field: "private"})

    def test_overnight_and_day_schedules(self):
        settings = Settings(active_hours=["22:00", "06:00"])
        self.assertTrue(settings.scheduled(datetime(2026, 11, 23, 23)))
        self.assertTrue(settings.scheduled(datetime(2026, 11, 23, 2)))
        self.assertFalse(settings.scheduled(datetime(2026, 11, 23, 12)))

    def test_no_bot_or_database_dependency_in_isolated_environment(self):
        for name in ("app", "sqlalchemy", "asyncpg", "aiogram", "telethon", "fastapi"):
            self.assertIsNone(importlib.util.find_spec(name), name)

    def test_autostart_does_not_embed_credentials_and_escapes_paths(self):
        config = Path("directory with spaces/scanner.yaml")
        for system in ("windows", "linux", "darwin"):
            text = definition(
                system, config, executable="C:/Program Files/Python/python.exe"
            )
            self.assertIn("sauh_network_scanner", text)
            self.assertNotIn(KEY, text)
            if system == "windows":
                import xml.etree.ElementTree as ET

                ET.fromstring(text)
                self.assertIn("LeastPrivilege", text)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.outbox = Outbox(self.temp.name)
        self.addCleanup(lambda: self.outbox.close() if self.outbox else None)

    def job(self):
        return dict(id=str(uuid4()), kind="vpn", check_kind="full")

    def observation(self):
        return dict(id=str(uuid4()), attempt_count=1, final=True)

    def test_saved_results_survive_restart_and_ack_is_selective(self):
        job = self.job()
        first = self.observation()
        second = self.observation()
        second["attempt_count"] = 2
        self.outbox.receive_jobs("vpn.full", [job])
        self.outbox.save_result(job, first)
        self.outbox.save_result(job, second)
        self.outbox.close()
        self.outbox = Outbox(self.temp.name)
        self.assertEqual(self.outbox.count(), 2)
        self.outbox.acknowledge([first["id"]])
        self.assertEqual(self.outbox.results(100)[0]["observation"]["id"], second["id"])

    def test_a_crashed_running_job_is_not_replayed_as_an_extra_success(self):
        job = self.job()
        self.outbox.receive_jobs("vpn.full", [job])
        self.outbox.take_jobs("vpn", "full", 1)
        self.outbox.close()
        self.outbox = Outbox(self.temp.name)
        self.assertEqual(self.outbox.take_jobs("vpn", "full", 1), [])

    def test_observation_identity_and_attempt_are_immutable(self):
        job = self.job()
        value = self.observation()
        self.outbox.save_result(job, value)
        with self.assertRaises(ValueError):
            self.outbox.save_result(job, {**value, "final": False})
        with self.assertRaises(ValueError):
            self.outbox.save_result(job, {**value, "id": str(uuid4())})

    def test_claim_request_id_survives_connection_loss(self):
        request = dict(request_id=str(uuid4()), kind="vpn", check_kind="full", count=2)
        self.assertEqual(self.outbox.claim_request("vpn.full", request), request)
        self.assertEqual(
            self.outbox.claim_request("vpn.full", {"request_id": str(uuid4())}), request
        )

    def test_two_process_instances_cannot_share_one_outbox(self):
        path = Path(self.temp.name) / "agent.lock"
        with DeviceLock(path):
            with self.assertRaises(ValueError):
                with DeviceLock(path):
                    pass

    def test_target_credentials_are_removed_after_final_ack(self):
        job = {**self.job(), "target": {"uri": "synthetic-private-target"}}
        self.outbox.receive_jobs("vpn.full", [job])
        value = self.observation()
        self.outbox.save_result(job, value)
        self.outbox.finish_job(job["id"])
        self.outbox.acknowledge([value["id"]])
        self.assertEqual(
            self.outbox.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0
        )


class APITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []

        async def endpoint(request):
            self.requests.append(request)
            if request.match_info["route"] == "redirect":
                raise web.HTTPFound("/sink")
            return web.json_response(
                {"server_time": datetime.now(timezone.utc).isoformat(), "accepted": []}
            )

        app = web.Application()
        app.router.add_post("/v1/scanner/{route}", endpoint)
        self.server = TestServer(app)
        await self.server.start_server()
        self.addAsyncCleanup(self.server.close)
        settings = Settings(
            api_url=str(self.server.make_url("")).rstrip("/"),
            allow_http_loopback=True,
            API_KEY=KEY,
        )
        self.api = APIClient(settings)
        await self.api.__aenter__()
        self.addAsyncCleanup(self.api.__aexit__, None, None, None)

    async def test_https_requests_use_connect_and_keep_the_api_key_inside_tls(self):
        attempts = []

        async def reject_connect(reader, writer):
            try:
                attempts.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        async with await asyncio.start_server(reject_connect, "127.0.0.1", 0) as proxy:
            port = proxy.sockets[0].getsockname()[1]
            settings = Settings(
                api_url="https://127.0.0.1:1",
                api_proxy=f"http://user:password@127.0.0.1:{port}",
                API_KEY=KEY,
            )
            async with APIClient(settings) as api:
                for route in ("heartbeat", "jobs/claim", "results", "logs"):
                    with self.subTest(route=route), self.assertRaises(APIError) as error:
                        await api.post(route, {})
                    self.assertEqual(error.exception.code, "connection_failed")
        self.assertEqual(len(attempts), 4)
        for request in attempts:
            self.assertTrue(request.startswith(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n"))
            self.assertIn(b"Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==", request)
            self.assertNotIn(KEY.encode(), request)

    async def test_socks5h_sends_the_hostname_and_handles_proxy_rejection(self):
        targets = []

        async def reject_target(reader, writer):
            try:
                _, method_count = await reader.readexactly(2)
                await reader.readexactly(method_count)
                writer.write(b"\x05\x00")
                await writer.drain()
                _, _, _, address_type = await reader.readexactly(4)
                address_length = (await reader.readexactly(1))[0] if address_type == 3 else 4
                targets.append((address_type, await reader.readexactly(address_length)))
                await reader.readexactly(2)
                writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        async with await asyncio.start_server(reject_target, "127.0.0.1", 0) as proxy:
            port = proxy.sockets[0].getsockname()[1]
            settings = Settings(
                api_url="https://localhost:1",
                api_proxy=f"socks5h://127.0.0.1:{port}",
                API_KEY=KEY,
            )
            async with APIClient(settings) as api:
                with self.assertRaises(APIError) as error:
                    await api.post("heartbeat", {})
                self.assertEqual(error.exception.code, "connection_failed")
        self.assertEqual(targets, [(3, b"localhost")])

    async def test_only_own_key_is_sent_and_redirects_are_not_followed(self):
        await self.api.post("heartbeat", {})
        self.assertEqual(self.requests[0].headers["Authorization"], "Bearer " + KEY)
        with self.assertRaises(APIError):
            await self.api.post("redirect", {})
        self.assertEqual(len(self.requests), 2)

    async def test_monotonic_server_clock_survives_local_wall_clock_jump(self):
        await self.api.post("heartbeat", {})
        before = self.api.server_now()
        with patch(
            "sauh_network_scanner.api.time.time", return_value=time.time() + 86400
        ):
            self.assertLess(abs(self.api.server_now() - before), 1)

    async def test_connection_failure_keeps_outbox_results(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = Outbox(directory)
            try:
                job = dict(id=str(uuid4()))
                value = dict(id=str(uuid4()), attempt_count=1)
                outbox.save_result(job, value)
                runtime = Runtime(self.api.settings, outbox, api=self.api)
                await self.server.close()
                with self.assertRaises(APIError):
                    await runtime.publish_once()
                self.assertEqual(outbox.count(), 1)
            finally:
                outbox.close()
