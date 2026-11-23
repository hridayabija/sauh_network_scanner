"""Independent leased workers and durable bulk publishers for an intermittent PC."""

import asyncio
from datetime import datetime, timezone
import logging
import platform
import random
import time
from uuid import UUID, uuid4

import psutil

from . import __version__
from .api import APIClient, APIError
from .wire import Lease
from .checks.core.vpn import VPNSettings
from .checks.core.mtproxy import MTProxySettings
from .checks.domain.vpn import VPNSpec
from .checks.domain.mtproxy import ProxySpec
from .checks.vpn.core import CoreRunner, CoreError, terminate
from .checks.services.vpn_check import check_many as vpn_check, VPNCheckContext
from .checks.services.mtproxy_check import check_many as mt_check, MTProxyCheckContext


logger = logging.getLogger(__name__)


class Runtime:
    def __init__(
        self,
        settings,
        outbox,
        *,
        api=None,
        vpn_checker=vpn_check,
        mtproxy_checker=mt_check,
    ):
        self.settings, self.outbox = settings, outbox
        self.api = api or APIClient(settings)
        self.vpn_checker, self.mtproxy_checker = vpn_checker, mtproxy_checker
        self.stop = asyncio.Event()
        self.ready = asyncio.Event()
        self.tasks = []
        self.core = None
        self.core_available = False
        self.core_version = None
        self.failures = {}

    def record_log(self, event, message, level="INFO"):
        # Only controlled messages/counters are sent; no exception string, URI,
        # Authorization header, target secret or local configuration is included.
        self.outbox.log(
            dict(id=str(uuid4()), level=level, event=event, message=message)
        )
        logger.log(getattr(logging, level), "%s: %s", event, message)

    def paused(self):
        if not self.settings.scheduled():
            return True
        if self.settings.pause_on_battery:
            battery = psutil.sensors_battery()
            if battery is not None and not battery.power_plugged:
                return True
        return False

    async def wait(self, seconds):
        try:
            await asyncio.wait_for(self.stop.wait(), timeout=max(0.01, seconds))
        except TimeoutError:
            pass

    async def failed(self, lane, error):
        count = self.failures.get(lane, 0) + 1
        self.failures[lane] = count
        if count == 1 or count % 10 == 0:
            self.record_log("api.unavailable", f"{lane}: {error.code}", "WARNING")
        delay = min(
            self.settings.retry_max_seconds, max(error.retry_after, 2 ** min(count, 8))
        )
        await self.wait(delay * random.uniform(0.8, 1.2))

    async def prepare(self):
        if self.settings.vpn_full_workers or self.settings.vpn_health_workers:
            core_config = VPNSettings(
                core_path=self.settings.core_path,
                core_start_concurrency=self.settings.core_start_concurrency,
            )
            self.core = CoreRunner(core_config)
            try:
                await self.core.prepare()
                self.core_available = True
                process = await asyncio.create_subprocess_exec(
                    self.core.binary,
                    "version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    raw, _ = await asyncio.wait_for(process.communicate(), 10)
                finally:
                    await terminate(process)
                self.core_version = raw.decode(errors="replace").splitlines()[0][:64]
            except (CoreError, OSError, TimeoutError):
                self.record_log(
                    "core.unavailable",
                    "VPN disabled until sing-box is installed; MTProxy can continue",
                    "WARNING",
                )

    async def heartbeat(self):
        while not self.stop.is_set():
            body = dict(
                protocol_version=1,
                agent_version=__version__,
                platform=platform.system().lower(),
                vpn=self.core_available
                and bool(
                    self.settings.vpn_full_workers or self.settings.vpn_health_workers
                ),
                mtproxy=bool(
                    self.settings.mtproxy_full_workers
                    or self.settings.mtproxy_health_workers
                ),
                core_version=self.core_version,
                pending_results=self.outbox.count(),
                paused=self.paused(),
            )
            try:
                result = await self.api.post("heartbeat", body)
                if result.get("protocol_version") != 1:
                    raise APIError(200, "unsupported_protocol")
                self.ready.set()
                self.failures["heartbeat"] = 0
                await self.wait(self.settings.heartbeat_seconds)
            except APIError as exc:
                await self.failed("heartbeat", exc)

    async def run_job(self, job):
        try:
            if (
                datetime.fromisoformat(job["expires_at"]).timestamp()
                <= self.api.server_now()
            ):
                return
            kind, phase = job["kind"], job["check_kind"]
            values = job["policy"]["settings"]
            if kind == "vpn":
                config = VPNSettings.model_validate(
                    {**values, "core_path": self.settings.core_path, "concurrency": 1}
                )
                spec = VPNSpec.from_uri(job["target"]["uri"])
                checker = self.vpn_checker
                options = dict(
                    core=self.core,
                    contexts={
                        spec.key: VPNCheckContext(
                            job["previously_verified"], job["preferred_ip"]
                        )
                    },
                )
            else:
                config = MTProxySettings.model_validate({**values, "concurrency": 1})
                spec = ProxySpec.make(**job["target"])
                checker = self.mtproxy_checker
                options = dict(
                    contexts={
                        spec.key: MTProxyCheckContext(
                            job["previously_verified"], job["preferred_ip"]
                        )
                    }
                )
            if (
                spec.key != job["target_key"]
                or config.validation_key != job["policy"]["validation_key"]
                or (
                    config.health_validation_key
                    != job["policy"]["health_validation_key"]
                )
            ):
                raise ValueError("Target or policy identity does not match")

            async def save(spec, observation):
                # A monotonic server-time anchor survives a local clock jump.
                measured = datetime.fromtimestamp(
                    self.api.server_now() - observation.duration_ms / 1000, timezone.utc
                )
                observation = observation.model_copy(
                    update={"round_id": UUID(job["id"]), "checked_at": measured}
                )
                self.outbox.save_result(job, observation.model_dump(mode="json"))

            await checker(
                [spec],
                config,
                save,
                stop=self.stop,
                health_only=phase == "health",
                **options,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.record_log(
                "job.local_error",
                f"{job.get('kind', 'unknown')}: {type(exc).__name__}",
                "WARNING",
            )
        finally:
            self.outbox.finish_job(job["id"])

    async def lane(self, kind, phase):
        name = kind + "." + phase
        workers = self.settings.workers(kind, phase)
        active = set()
        try:
            while not self.stop.is_set():
                active = {task for task in active if not task.done()}
                if (
                    not self.ready.is_set()
                    or self.paused()
                    or (kind == "vpn" and not self.core_available)
                ):
                    await self.wait(self.settings.poll_seconds)
                    continue
                if (
                    self.outbox.count() >= self.settings.max_pending_results
                    or self.outbox.bytes() >= self.settings.max_storage_mb * 1024 * 1024
                ):
                    await self.wait(self.settings.poll_seconds)
                    continue
                available = workers - len(active)
                if available <= 0:
                    await self.wait(0.2)
                    continue
                jobs = self.outbox.take_jobs(kind, phase, available)
                if not jobs:
                    payload = self.outbox.claim_request(
                        name,
                        dict(
                            request_id=str(uuid4()),
                            kind=kind,
                            check_kind=phase,
                            count=available,
                        ),
                    )
                    try:
                        response = await self.api.post("jobs/claim", payload)
                        jobs_response = response.get("jobs", [])
                        if (
                            not isinstance(jobs_response, list)
                            or len(jobs_response) > 100
                        ):
                            raise APIError(200, "invalid_jobs")
                        try:
                            jobs_response = [
                                Lease.model_validate(job).model_dump(mode="json")
                                for job in jobs_response
                            ]
                        except ValueError:
                            raise APIError(200, "invalid_job_envelope") from None
                        self.outbox.receive_jobs(name, jobs_response)
                        jobs = self.outbox.take_jobs(kind, phase, available)
                        self.failures[name] = 0
                    except APIError as exc:
                        await self.failed(name, exc)
                        continue
                for job in jobs:
                    active.add(
                        asyncio.create_task(self.run_job(job), name="job-" + job["id"])
                    )
                if not jobs:
                    await self.wait(self.settings.poll_seconds)
        finally:
            # Checkers stop between attempts, finish their bounded active request,
            # and persist any completed observations before the publisher drain.
            await asyncio.gather(*active, return_exceptions=True)

    async def publish_once(self):
        rows = self.outbox.results(self.settings.publish_batch_size)
        if not rows:
            return
        response = await self.api.post("results", dict(results=rows))
        posted = {row["observation"]["id"] for row in rows}
        accepted = set(response.get("accepted", []))
        rejected = {item.get("id") for item in response.get("rejected", [])}
        if not accepted.union(rejected) <= posted:
            raise APIError(200, "invalid_acknowledgement")
        # Every structured per-item rejection is terminal; HTTP/network errors
        # never acknowledge data. The authoritative server does not revive old jobs.
        self.outbox.acknowledge(accepted | rejected)
        if rejected:
            self.record_log(
                "results.rejected",
                f"{len(rejected)} observations rejected by API",
                "WARNING",
            )

    async def publish(self):
        while not self.stop.is_set():
            try:
                await self.publish_once()
                self.failures["results"] = 0
                await self.wait(self.settings.publish_seconds)
            except APIError as exc:
                await self.failed("results", exc)

    async def logs(self):
        while not self.stop.is_set():
            rows = self.outbox.logs()
            try:
                if rows:
                    response = await self.api.post("logs", dict(logs=rows))
                    posted = {row["id"] for row in rows}
                    accepted = set(response.get("accepted", []))
                    if not accepted <= posted:
                        raise APIError(200, "invalid_acknowledgement")
                    self.outbox.acknowledge_logs(accepted)
                await self.wait(10)
            except APIError as exc:
                await self.wait(min(self.settings.retry_max_seconds, exc.retry_after))

    async def run(self):
        await self.prepare()
        async with self.api:
            self.record_log("agent.started", "Validation agent started")
            operations = [
                ("heartbeat", self.heartbeat),
                ("publisher", self.publish),
                ("logs", self.logs),
            ]
            operations += [
                (
                    kind + "." + phase,
                    lambda kind=kind, phase=phase: self.lane(kind, phase),
                )
                for kind in ("vpn", "mtproxy")
                for phase in ("full", "health")
                if self.settings.workers(kind, phase)
            ]
            self.tasks = [
                asyncio.create_task(self.supervise(name, operation), name=name)
                for name, operation in operations
            ]
            try:
                await self.stop.wait()
            finally:
                self.stop.set()
                try:
                    async with asyncio.timeout(210):
                        await asyncio.gather(*self.tasks, return_exceptions=True)
                except TimeoutError:
                    for task in self.tasks:
                        task.cancel()
                    await asyncio.gather(*self.tasks, return_exceptions=True)
                try:
                    async with asyncio.timeout(self.settings.request_timeout_seconds):
                        await self.publish_once()
                except (APIError, TimeoutError):
                    pass

    async def supervise(self, name, operation):
        while not self.stop.is_set():
            try:
                await operation()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Worker %s restarting after %s", name, type(exc).__name__)
                await self.wait(5)
