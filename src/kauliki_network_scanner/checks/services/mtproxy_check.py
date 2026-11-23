"""Bounded full and health workers with immutable, immediately saved attempts."""

import asyncio
from dataclasses import dataclass
from functools import partial
import logging
import time

from kauliki_network_scanner.checks.domain.mtproxy import (
    CHECKER_VERSION,
    DCObservation,
    ProxyObservation,
)
from kauliki_network_scanner.checks.mtproxy.protocol import (
    MTProxyCheckerError,
    check_proxy,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MTProxyCheckContext:
    previously_verified: bool = False
    preferred_ip: str | None = None


async def check_many(
    specs,
    config,
    save,
    *,
    stop=None,
    geoip=None,
    checker=check_proxy,
    contexts=None,
    health_only=False,
    semaphore=None,
):
    stop = stop or asyncio.Event()
    specs = list(
        {spec.key: spec for spec in specs if spec.kind in config.proxy_kinds}.values()
    )
    queue = iter(specs)
    contexts = contexts or {}
    done = working = skipped = attempts_saved = 0
    claimed = {}
    started = time.monotonic()

    def claim_ip(spec, address):
        identity = address, spec.port, spec.secret
        owner = claimed.setdefault(identity, spec.key)
        return owner == spec.key

    async def invoke(spec, context):
        options = dict(claim_ip=partial(claim_ip, spec))
        if checker is check_proxy:
            options.update(preferred_ip=context.preferred_ip, health_only=health_only)
        try:
            if semaphore is None:
                return await checker(spec, config, geoip, **options)
            async with semaphore:
                return await checker(spec, config, geoip, **options)
        except MTProxyCheckerError as error:
            logger.warning("MTProxy checker key=%s reason=%s", spec.key[:16], error)
            return ProxyObservation(
                checker_version=CHECKER_VERSION,
                validation_key=config.validation_key,
                health_validation_key=config.health_validation_key,
                samples=1 if health_only else config.samples,
                check_kind="health" if health_only else "full",
                checker_error=True,
                dcs=[
                    DCObservation(dc_id=dc, error=str(error)[:300])
                    for dc in config.dc_ids
                ],
            )

    async def worker():
        nonlocal done, working, skipped, attempts_saved
        while not stop.is_set():
            spec = next(queue, None)
            if spec is None:
                return
            context = contexts.get(spec.key, MTProxyCheckContext())
            round_id, errors = None, []
            for attempt in range(config.recheck_attempts + 1):
                if stop.is_set():
                    break
                observation = await invoke(spec, context)
                if observation is None:
                    skipped += 1
                    logger.info(
                        "MTProxy skipped duplicate endpoint key=%s",
                        spec.key[:16],
                        extra={"scanner_detail": True},
                    )
                    break
                round_id = round_id or observation.id
                retry = (
                    attempt < config.recheck_attempts
                    and not observation.working
                    and not observation.checker_error
                    and (
                        health_only
                        or context.previously_verified
                        or observation.reachable
                    )
                )
                if not observation.working:
                    errors.append(
                        next(
                            (dc.error for dc in observation.dcs if dc.error),
                            "incomplete check",
                        )
                    )
                observation = observation.model_copy(
                    update=dict(
                        round_id=round_id,
                        check_kind="health" if health_only else "full",
                        final=not retry,
                        attempt_count=attempt + 1,
                        attempt_errors=list(errors),
                    )
                )
                await save(spec, observation)
                attempts_saved += 1
                if observation.final:
                    done += 1
                    working += bool(observation.working)
                    break
                if config.recheck_delay_seconds:
                    try:
                        await asyncio.wait_for(
                            stop.wait(), config.recheck_delay_seconds
                        )
                        break
                    except TimeoutError:
                        pass

    logger.info(
        "Checking %d proxies, %d workers (%s)",
        len(specs),
        config.concurrency,
        "health" if health_only else "full",
    )

    async def progress():
        while True:
            await asyncio.sleep(30)
            logger.info(
                "Progress: %d/%d rounds, %d attempts saved, %d working, %.0fs elapsed",
                done,
                len(specs),
                attempts_saved,
                working,
                time.monotonic() - started,
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
        "Saved %d results (%d working); %d attempts; duplicate endpoints skipped %d; pending %d",
        done,
        working,
        attempts_saved,
        skipped,
        len(specs) - done - skipped,
    )
    return done
