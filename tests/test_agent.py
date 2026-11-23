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

from kauliki_network_scanner.api import APIClient, APIError
from kauliki_network_scanner.autostart import definition
from kauliki_network_scanner.config import Settings
from kauliki_network_scanner.runtime import Runtime
from kauliki_network_scanner.storage import DeviceLock, Outbox


KEY = "synthetic-only-key-" + "A" * 40


class ConfigurationTests(unittest.TestCase):
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
            self.assertIn("kauliki_network_scanner", text)
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
            "kauliki_network_scanner.api.time.time", return_value=time.time() + 86400
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
