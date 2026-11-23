"""Persist attempts immediately; count only completed full logical rounds."""

import asyncio
from collections import Counter
from dataclasses import dataclass
import logging
import time

from sauh_network_scanner.checks.domain.vpn import CHECKER_VERSION, VPNObservation
from sauh_network_scanner.checks.vpn.core import (
    CoreConfigError,
    CoreError,
    CoreRunner,
)
from sauh_network_scanner.checks.vpn.probe import check_vpn


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VPNCheckContext:
    previously_verified: bool = False
    preferred_ip: str | None = None


async def check_many(
    specs,
    config,
    save,
    *,
    stop=None,
    geoip=None,
    core=None,
    checker=check_vpn,
    contexts=None,
    health_only=False,
    semaphore=None,
):
    if not specs:
        return 0
    if core is None and checker is check_vpn:
        core = CoreRunner(config)
        await core.prepare()
    stop = stop or asyncio.Event()
    queue = iter(specs)
    contexts = contexts or {}
    checked = working = attempts_saved = 0
    retry_limit = (
        config.health_recheck_attempts
        if health_only and config.health_recheck_attempts is not None
        else config.recheck_attempts
    )
    failures = Counter()
    started = time.monotonic()

    async def invoke(spec, context, attempt):
        if checker is check_vpn:
            return await checker(
                spec,
                config,
                core,
                geoip,
                preferred_ip=context.preferred_ip,
                attempt=attempt,
                quick_retry=bool(attempt),
                health_only=health_only,
            )
        return await checker(spec, config, core, geoip)

    async def run(spec, context, attempt):
        began = time.monotonic()
        try:
            if semaphore is None:
                return await invoke(spec, context, attempt)
            async with semaphore:
                return await invoke(spec, context, attempt)
        except CoreError as error:
            logger.warning(
                "VPN checker key=%s kind=%s reason=%s",
                spec.key[:16],
                "health" if health_only else "full",
                error,
            )
            return VPNObservation(
                samples=1 if health_only else config.samples,
                checker_version=CHECKER_VERSION,
                validation_key=config.validation_key,
                health_validation_key=config.health_validation_key,
                check_kind="health" if health_only else "full",
                duration_ms=(time.monotonic() - began) * 1000,
                checker_error=not isinstance(error, CoreConfigError),
                config_error=isinstance(error, CoreConfigError),
                error=str(error)[:300],
                stage_errors={"checker": str(error)[:300]},
            )

    async def worker():
        nonlocal checked, working, attempts_saved
        while not stop.is_set():
            spec = next(queue, None)
            if spec is None:
                return
            context = contexts.get(spec.key, VPNCheckContext())
            round_id = None
            errors, duration = [], 0.0
            for attempt in range(retry_limit + 1):
                if stop.is_set():
                    break
                if attempt:
                    logger.info(
                        "VPN recheck key=%s kind=%s attempt=%d/%d",
                        spec.key[:16],
                        "health" if health_only else "full",
                        attempt + 1,
                        retry_limit + 1,
                        extra={"scanner_detail": True},
                    )
                observation = await run(spec, context, attempt)
                round_id = round_id or observation.id
                duration += observation.duration_ms
                retry = (
                    attempt < retry_limit
                    and not observation.complete
                    and not observation.safety_error
                    and not observation.checker_error
                    and not observation.config_error
                    and (
                        health_only
                        or context.previously_verified
                        or observation.working
                    )
                )
                if not observation.complete:
                    errors.append(observation.error or "incomplete check")
                observation = observation.model_copy(
                    update=dict(
                        round_id=round_id,
                        check_kind="health" if health_only else "full",
                        final=not retry,
                        attempt_count=attempt + 1,
                        attempt_errors=list(errors),
                        duration_ms=duration,
                    )
                )
                # Persist before the next request or delay. UUIDs are immutable;
                # a retry is an attempt of this round, not another qualification.
                await save(spec, observation)
                attempts_saved += 1
                if observation.final:
                    checked += 1
                    working += bool(observation.working)
                    if not observation.complete:
                        failures[observation.error or "incomplete check"] += 1
                    break
                if config.recheck_delay_seconds:
                    try:
                        await asyncio.wait_for(
                            stop.wait(), config.recheck_delay_seconds
                        )
                        break
                    except TimeoutError:
                        pass

    async def progress():
        while True:
            await asyncio.sleep(30)
            elapsed = time.monotonic() - started
            logger.info(
                "VPN %s: %d/%d rounds, %d attempts saved, %d working, %.2f nodes/s; failures=%s",
                "health" if health_only else "full",
                checked,
                len(specs),
                attempts_saved,
                working,
                checked / max(elapsed, 0.001),
                dict(failures.most_common(5)),
            )

    reporter = asyncio.create_task(progress())
    try:
        async with asyncio.TaskGroup() as group:
            for _ in range(config.concurrency):
                group.create_task(worker())
    finally:
        reporter.cancel()
        await asyncio.gather(reporter, return_exceptions=True)
    logger.info(
        "VPN %s: %d rounds, %d attempts saved, %d working",
        "health" if health_only else "full",
        checked,
        attempts_saved,
        working,
    )
    return checked
