from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock
from uuid import uuid4

from aiohttp import web
from aiohttp.test_utils import TestServer

from sauh_network_scanner.api import APIClient, APIError
from sauh_network_scanner.config import Settings
from sauh_network_scanner.logging import configure_logging
from sauh_network_scanner.runtime import Runtime
from sauh_network_scanner.storage import Outbox
from sauh_network_scanner.checks.core.mtproxy import MTProxySettings
from sauh_network_scanner.checks.domain.mtproxy import ProxySpec, ProxyObservation, DCObservation


KEY = "synthetic-key-" + "A" * 40


class APIObservabilityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.status, self.body = 503, {"error": "temporarily_unavailable"}

        async def endpoint(request):
            return web.json_response(self.body, status=self.status)

        app = web.Application()
        app.router.add_post("/v1/scanner/{route}", endpoint)
        self.server = TestServer(app)
        await self.server.start_server()
        self.addAsyncCleanup(self.server.close)
        self.api = APIClient(
            Settings(
                api_url=str(self.server.make_url("")).rstrip("/"),
                allow_http_loopback=True,
                API_KEY=KEY,
            )
        )
        await self.api.__aenter__()
        self.addAsyncCleanup(self.api.__aexit__, None, None, None)

    async def test_failure_has_http_status_and_known_code_and_recovery_preserves_results(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = Outbox(directory)
            self.addCleanup(outbox.close)
            value = dict(id=str(uuid4()), attempt_count=1)
            outbox.save_result({"id": str(uuid4())}, value)
            runtime = Runtime(self.api.settings, outbox, api=self.api)
            with self.assertRaises(APIError) as error:
                await runtime.publish_once()
            self.assertEqual(error.exception.status, 503)
            self.assertEqual(error.exception.code, "temporarily_unavailable")
            runtime.wait = AsyncMock()
            with self.assertLogs("sauh_network_scanner.runtime", level="WARNING") as captured:
                await runtime.failed("results", error.exception)
            self.assertIn("HTTP=503", captured.output[0])
            self.assertIn("pending=1", captured.output[0])
            self.assertEqual(outbox.count(), 1)
            self.status, self.body = 200, {"accepted": [value["id"]]}
            await runtime.publish_once()
            with self.assertLogs("sauh_network_scanner.runtime", level="INFO") as captured:
                runtime.recovered("results")
            self.assertIn("api.recovered", captured.output[0])
            self.assertEqual(outbox.count(), 0)
            self.assertEqual(runtime.delivered, 1)

    async def test_unknown_server_error_cannot_echo_credentials(self):
        self.body = {"error": KEY, "detail": "vless://private"}
        with self.assertRaises(APIError) as error:
            await self.api.post("results", {})
        self.assertEqual(error.exception.code, "temporarily_unavailable")
        self.assertNotIn(KEY, str(error.exception))

    async def test_terminal_rejection_is_logged_with_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = Outbox(directory)
            self.addCleanup(outbox.close)
            value = dict(id=str(uuid4()), attempt_count=1)
            outbox.save_result({"id": str(uuid4())}, value)
            self.status, self.body = (
                200,
                {"rejected": [{"id": value["id"], "code": "expired_result"}]},
            )
            runtime = Runtime(self.api.settings, outbox, api=self.api)
            with self.assertLogs("sauh_network_scanner.runtime", level="WARNING") as captured:
                await runtime.publish_once()
            self.assertIn("expired_result", captured.output[0])
            self.assertEqual(runtime.rejected, 1)
            self.assertEqual(outbox.count(), 0)


class RuntimeObservabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_progress_counts_actual_completed_attempts_and_job_credentials_stay_private(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = Outbox(directory)
            self.addCleanup(outbox.close)
            config = MTProxySettings(samples=1, dc_ids=[1])
            spec = ProxySpec.make("8.8.8.8", 443, "a" * 32)
            job = dict(
                id=str(uuid4()),
                kind="mtproxy",
                check_kind="full",
                expires_at=(datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
                policy=dict(
                    settings=config.model_dump(),
                    validation_key=config.validation_key,
                    health_validation_key=config.health_validation_key,
                ),
                target=dict(host=spec.host, port=spec.port, secret=spec.secret),
                target_key=spec.key,
                previously_verified=False,
                preferred_ip="8.8.8.8",
            )
            observation = ProxyObservation(
                samples=1,
                dcs=[
                    DCObservation(
                        dc_id=1, ip="8.8.8.8", handshake_ok=True, rtt_ms=[10], first_response_ms=10
                    )
                ],
            )

            async def check(specs, settings, save, **options):
                await save(specs[0], observation)

            runtime = Runtime(Settings(), outbox, mtproxy_checker=check)
            runtime.ready.set()
            await runtime.run_job(job)
            text = runtime.progress_text()
            self.assertIn("mtproxy.full: active=0 claimed=0 completed=1 successful=1", text)
            self.assertEqual(runtime.counts["mtproxy.full"]["attempts"], 1)
            self.assertIn("active=0", text)
            self.assertNotIn(spec.secret, text)
            self.assertEqual(outbox.count(), 1)

    async def test_clean_stop_publishes_lifecycle_logs_and_paused_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = Outbox(directory)
            self.addCleanup(outbox.close)
            api = AsyncMock()
            messages = []

            async def post(route, body):
                messages.append((route, body))
                return {"accepted": [row["id"] for row in body.get("logs", [])]}

            api.post.side_effect = post
            settings = Settings(
                vpn_full_workers=0,
                vpn_health_workers=0,
                mtproxy_full_workers=0,
                mtproxy_health_workers=0,
            )
            runtime = Runtime(settings, outbox, api=api)
            runtime.stop.set()
            await runtime.run()
            heartbeat = next(body for route, body in messages if route == "heartbeat")
            self.assertTrue(heartbeat["paused"])
            logs = next(body for route, body in messages if route == "logs")["logs"]
            self.assertEqual([entry["event"] for entry in logs], ["agent.started", "agent.stopped"])
            self.assertEqual(outbox.logs(), [])

    def test_rotating_logs_exclude_probe_library_messages(self):
        with tempfile.TemporaryDirectory() as directory:
            logger = logging.getLogger("sauh_network_scanner.runtime")
            previous = logger.handlers[:], logger.level, logger.propagate
            logger.handlers = []
            try:
                configure_logging(Settings(state_directory=directory))
                logger.info("agent.progress: completed=7")
                logging.getLogger("sauh_network_scanner.checks").error("vless://private")
                text = (Path(directory) / "scanner.log").read_text()
                self.assertIn("completed=7", text)
                self.assertNotIn("private", text)
            finally:
                for handler in logger.handlers:
                    handler.close()
                logger.handlers, logger.level, logger.propagate = previous
