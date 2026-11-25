"""Independent leased workers and durable bulk publishers for an intermittent PC."""

import asyncio
from collections import Counter
from datetime import datetime, timezone
import logging
import platform
import random
import time
from uuid import UUID, uuid4

import psutil

from . import __version__
from .api import APIClient, APIError, safe_code
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
        self.started = time.monotonic()
        self.counts = {
            kind + "." + phase: Counter()
            for kind in ("vpn", "mtproxy")
            for phase in ("full", "health")
        }
        self.inflight = Counter()
        self.delivered = self.rejected = 0
        self.last_failure_log = {}

    def record_log(self, event, message, level="INFO"):
        # Only controlled messages/counters are sent; no exception string, URI,
        # Authorization header, target secret or local configuration is included.
        if level == "DEBUG" and self.settings.log_level != "DEBUG":
            return
        self.outbox.log(dict(id=str(uuid4()), level=level, event=event, message=message))
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
        delay = min(self.settings.retry_max_seconds, max(error.retry_after, 2 ** min(count, 8)))
        delay *= random.uniform(1, 1.2)
        now = time.monotonic()
        if count == 1 or now - self.last_failure_log.get(lane, 0) >= 60:
            self.last_failure_log[lane] = now
            self.record_log(
                "api.unavailable",
                f"lane={lane} HTTP={error.status} code={error.code} "
                f"failures={count} retry_seconds={delay:.1f} pending={self.outbox.count()}",
                "WARNING",
            )
        await self.wait(delay)

    def recovered(self, lane):
        count = self.failures.get(lane, 0)
        if count:
            self.record_log(
                "api.recovered", f"lane={lane} failures={count} pending={self.outbox.count()}"
            )
        self.failures[lane] = 0

    def progress_text(self, state=None):
        state = state or (
            "paused"
            if self.paused()
            else "waiting_api"
            if not self.ready.is_set()
            else "backlog"
            if (
                self.outbox.count() >= self.settings.max_pending_results
                or self.outbox.bytes() >= self.settings.max_storage_mb * 1024 * 1024
            )
            else "api_degraded"
            if any(self.failures.values())
            else "working"
        )
        lanes = "; ".join(
            f"{name}: active={self.inflight[name]} claimed={counts['claimed']} "
            f"completed={counts['completed']} successful={counts['working']} expired={counts['expired']} "
            f"attempts={counts['attempts']} local_errors={counts['errors']}"
            for name, counts in self.counts.items()
            if self.settings.workers(*name.split("."))
        )
        return (
            f"state={state} uptime_seconds={int(time.monotonic() - self.started)} "
            f"delivered={self.delivered} rejected={self.rejected} pending={self.outbox.count()} "
            f"storage_mb={self.outbox.bytes() / 1024 / 1024:.1f}; {lanes}"
        )

    async def progress(self):
        previous_pause = None
        while not self.stop.is_set():
            paused = self.paused()
            if previous_pause is not None and paused != previous_pause:
                self.record_log(
                    "agent.paused" if paused else "agent.resumed", "Schedule/battery state changed"
                )
            previous_pause = paused
            self.record_log("agent.progress", self.progress_text())
            await self.wait(self.settings.progress_seconds)

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

    def heartbeat_body(self):
        return dict(
            protocol_version=1,
            agent_version=__version__,
            platform=platform.system().lower(),
            vpn=self.core_available
            and bool(self.settings.vpn_full_workers or self.settings.vpn_health_workers),
            mtproxy=bool(
                self.settings.mtproxy_full_workers or self.settings.mtproxy_health_workers
            ),
            core_version=self.core_version,
            pending_results=self.outbox.count(),
            paused=self.paused(),
        )

    async def heartbeat(self):
        while not self.stop.is_set():
            body = self.heartbeat_body()
            try:
                result = await self.api.post("heartbeat", body)
                if result.get("protocol_version") != 1:
                    raise APIError(200, "unsupported_protocol")
                self.ready.set()
                self.recovered("heartbeat")
                await self.wait(self.settings.heartbeat_seconds)
            except APIError as exc:
                await self.failed("heartbeat", exc)

    async def run_job(self, job):
        name = job["kind"] + "." + job["check_kind"]
        self.inflight[name] += 1
        try:
            if datetime.fromisoformat(job["expires_at"]).timestamp() <= self.api.server_now():
                self.counts[name]["expired"] += 1
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
                        spec.key: VPNCheckContext(job["previously_verified"], job["preferred_ip"])
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
                or (config.health_validation_key != job["policy"]["health_validation_key"])
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
                self.counts[name]["attempts"] += 1
                if observation.final:
                    working = (
                        observation.available
                        if kind == "vpn" and phase == "health"
                        else observation.working
                    )
                    self.counts[name]["completed"] += 1
                    self.counts[name]["working"] += bool(working)
                self.record_log(
                    "job.observed",
                    f"lane={name} assignment={job['id']} attempt={observation.attempt_count} "
                    f"final={observation.final} checker_error={observation.checker_error} duration_ms={observation.duration_ms:.0f}",
                    "DEBUG",
                )

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
            self.counts[name]["errors"] += 1
            self.record_log(
                "job.local_error",
                f"lane={name} assignment={job['id']} error={type(exc).__name__}",
                "WARNING",
            )
        finally:
            self.inflight[name] -= 1
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
                        if not isinstance(jobs_response, list) or len(jobs_response) > 100:
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
                        self.recovered(name)
                    except APIError as exc:
                        await self.failed(name, exc)
                        continue
                for job in jobs:
                    self.counts[name]["claimed"] += 1
                    self.record_log("jobs.claimed", f"lane={name} assignment={job['id']}", "DEBUG")
                    active.add(asyncio.create_task(self.run_job(job), name="job-" + job["id"]))
                if not jobs:
                    await self.wait(self.settings.poll_seconds)
        finally:
            # Checkers stop between attempts, finish their bounded active request,
            # and persist any completed observations before the publisher drain.
            await asyncio.gather(*active, return_exceptions=True)

    async def publish_once(self):
        rows = self.outbox.results(self.settings.publish_batch_size)
        if not rows:
            return False
        response = await self.api.post("results", dict(results=rows))
        posted = {row["observation"]["id"] for row in rows}
        accepted = set(response.get("accepted", []))
        rejected = {item.get("id") for item in response.get("rejected", [])}
        if not accepted.union(rejected) <= posted:
            raise APIError(200, "invalid_acknowledgement")
        # Every structured per-item rejection is terminal; HTTP/network errors
        # never acknowledge data. The authoritative server does not revive old jobs.
        self.outbox.acknowledge(accepted | rejected)
        self.delivered += len(accepted)
        self.rejected += len(rejected)
        if rejected:
            self.record_log(
                "results.rejected",
                f"count={len(rejected)} reasons="
                + str(
                    dict(
                        Counter(
                            safe_code(item.get("code"), "unknown_rejection")
                            for item in response.get("rejected", [])
                        )
                    )
                ),
                "WARNING",
            )
        return True

    async def publish(self):
        while not self.stop.is_set():
            try:
                if await self.publish_once():
                    self.recovered("results")
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
                    self.recovered("logs")
                await self.wait(10)
            except APIError as exc:
                await self.failed("logs", exc)

    async def run(self):
        await self.prepare()
        async with self.api:
            self.record_log("agent.started", "Validation agent started; " + self.progress_text())
            operations = [
                ("heartbeat", self.heartbeat),
                ("publisher", self.publish),
                ("logs", self.logs),
                ("progress", self.progress),
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
                self.record_log("agent.stopped", self.progress_text("stopped"))
                try:
                    async with asyncio.timeout(self.settings.request_timeout_seconds):
                        await self.api.post("heartbeat", {**self.heartbeat_body(), "paused": True})
                        rows = self.outbox.logs()
                        response = await self.api.post("logs", dict(logs=rows))
                        accepted = set(response.get("accepted", []))
                        if not accepted <= {row["id"] for row in rows}:
                            raise APIError(200, "invalid_acknowledgement")
                        self.outbox.acknowledge_logs(accepted)
                except (APIError, TimeoutError):
                    pass

    async def supervise(self, name, operation):
        while not self.stop.is_set():
            try:
                await operation()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.record_log("worker.restarting", f"worker={name} error={type(exc).__name__} retry_seconds=5", "ERROR")
                await self.wait(5)
