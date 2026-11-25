"""Independent latency probes, exit GeoIP and confirmed bidirectional traffic."""

import asyncio
import ipaddress
import os
import re
import ssl
import time
from datetime import datetime, timezone

import aiohttp

from sauh_network_scanner.checks.domain.vpn import (
    CHECKER_VERSION,
    LatencyProbe,
    VPNObservation,
)
from sauh_network_scanner.checks.vpn.core import CoreError
from sauh_network_scanner.checks.vpn.network import resolve_public
from sauh_network_scanner.checks.vpn.tls_audit import TLSAuditError


class ProbeError(ValueError):
    pass


async def tcp_preflight(address, port, timeout):
    async with asyncio.timeout(timeout):
        try:
            _, writer = await asyncio.open_connection(address, port)
        except OSError as error:
            raise ProbeError(f"TCP connect failed: {type(error).__name__}") from error
        writer.close()
        await writer.wait_closed()


def parse_trace(body):
    try:
        values = dict(
            line.split("=", 1)
            for line in body.decode("ascii").splitlines()
            if "=" in line
        )
        address = ipaddress.ip_address(values["ip"])
        if not address.is_global:
            raise ValueError
        country = values.get("loc")
        country = (
            country
            if country and re.fullmatch(r"[A-Z]{2}", country) and country != "XX"
            else None
        )
        return str(address), country
    except (ValueError, KeyError, UnicodeError):
        raise ProbeError("invalid exit trace") from None


async def bounded_body(response, limit):
    body = bytearray()
    async for block in response.content.iter_chunked(65536):
        body.extend(block)
        if len(body) > limit:
            raise ProbeError("response exceeds size limit")
    return bytes(body)


def error_label(phase, error):
    detail = f": {error}" if isinstance(error, (ProbeError, TLSAuditError)) else ""
    return f"{phase}: {type(error).__name__}{detail}"[:300]


def unsafe_tls(error):
    # An alert, reset or malformed reply is not evidence of negotiated weak
    # cryptography. Confirmed policy violations must never use availability grace.
    return isinstance(error, TLSAuditError) and str(error) in {
        "negotiated TLS version is below the required minimum",
        "negotiated TLS cipher is not an allowed AEAD suite",
        "TLS compression is forbidden",
        "invalid or obsolete TLS ServerHello",
    }


async def probe_tunnel(
    session,
    proxy,
    proxy_headers,
    config,
    observation,
    geoip=None,
    *,
    on_phase=None,
    on_error=None,
    quick_retry=False,
    health_only=False,
):
    # auto_decompress=False still advertises gzip unless this header is explicit.
    # Keep all probe bodies uncompressed for bounded parsing and speed accounting.
    def request_options(url, extra_headers=None):
        headers = {"Accept-Encoding": "identity", **(extra_headers or {})}
        if url.startswith("http://"):
            # Plain HTTP forwarding needs authorization on the proxy request;
            # CONNECT uses proxy_headers. sing-box strips this before forwarding.
            headers.update(proxy_headers)
        return dict(
            proxy=proxy,
            proxy_headers=proxy_headers,
            allow_redirects=False,
            headers=headers,
        )

    def require_status(response, expected, label):
        if response.status == 407:
            raise CoreError("local sing-box inbound rejected proxy authentication")
        if response.status != expected:
            raise ProbeError(f"{label} returned HTTP {response.status}")

    def failed(label, error):
        if on_error:
            on_error(error)
        observation.stage_errors[label] = error_label(label, error)
        observation.error = next(iter(observation.stage_errors.values()))

    if on_phase:
        on_phase("probe")
    for url in config.health_probe_urls if health_only else config.probe_urls:
        probe = LatencyProbe(url=url)
        observation.latency_probes.append(probe)
        for sample in range(observation.samples):
            try:
                if sample:
                    await asyncio.sleep(config.sample_delay_seconds)
                started = time.monotonic()
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=config.probe_timeout_seconds),
                    **request_options(url),
                ) as response:
                    require_status(response, 204, "probe")
                    if await bounded_body(response, 256):
                        raise ProbeError("probe returned an unexpected body")
                elapsed = (time.monotonic() - started) * 1000
                if probe.first_response_ms is None:
                    probe.first_response_ms = elapsed
                    observation.first_response_ms = max(
                        observation.first_response_ms or 0, elapsed
                    )
                probe.rtt_ms.append(elapsed)
                observation.rtt_ms.append(elapsed)
                observation.last_reachable_at = datetime.now(timezone.utc)
            except (aiohttp.ClientError, TimeoutError, ProbeError) as error:
                probe.error = error_label("probe", error)
                failed(f"probe:{len(observation.latency_probes)}", error)
                if not observation.reachable:
                    break  # One failed request per URL until a real response appears.

    if health_only or not observation.reachable:
        return  # Never spend bandwidth on a tunnel with no validated response.

    if on_phase:
        on_phase("trace")
    try:
        async with session.get(
            config.trace_url,
            timeout=aiohttp.ClientTimeout(total=config.trace_timeout_seconds),
            **request_options(config.trace_url),
        ) as response:
            require_status(response, 200, "trace")
            if (
                response.headers.get("Content-Encoding", "identity").lower()
                != "identity"
            ):
                raise ProbeError("compressed trace response")
            exit_ip, _ = parse_trace(await bounded_body(response, 4096))
    except (aiohttp.ClientError, TimeoutError, ProbeError) as error:
        failed("trace", error)
    else:
        observation.exit_ip = exit_ip
        observation.country_code = None
        observation.geo_source = None

    if on_phase:
        on_phase("download")
    started = time.monotonic()
    download_url = config.download_url.replace("{bytes}", str(config.download_bytes))
    try:
        async with session.get(
            download_url,
            timeout=aiohttp.ClientTimeout(total=config.download_timeout_seconds),
            **request_options(download_url),
        ) as response:
            require_status(response, 200, "download")
            if (
                response.headers.get("Content-Encoding", "identity").lower()
                != "identity"
            ):
                raise ProbeError("compressed speed response")
            observation.download_first_response_ms = (time.monotonic() - started) * 1000
            transfer_started = time.monotonic()
            async for block in response.content.iter_chunked(65536):
                if observation.download_bytes + len(block) > config.download_bytes:
                    raise ProbeError("response exceeds size limit")
                observation.download_bytes += len(block)
            if observation.download_bytes != config.download_bytes:
                raise ProbeError("incomplete speed response")
        observation.download_ms = max(
            0.001, (time.monotonic() - transfer_started) * 1000
        )
        observation.download_ok = True
    except (aiohttp.ClientError, TimeoutError, ProbeError) as error:
        failed("download", error)

    if on_phase:
        on_phase("upload")

    async def upload_body():
        block = os.urandom(65536)
        while observation.upload_bytes < config.upload_bytes:
            chunk = block[
                : min(len(block), config.upload_bytes - observation.upload_bytes)
            ]
            observation.upload_bytes += len(chunk)
            yield chunk

    upload_url = config.upload_url.replace("{bytes}", str(config.upload_bytes))
    started = time.monotonic()
    try:
        async with session.post(
            upload_url,
            data=upload_body(),
            timeout=aiohttp.ClientTimeout(total=config.upload_timeout_seconds),
            **request_options(
                upload_url,
                {
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(config.upload_bytes),
                },
            ),
        ) as response:
            require_status(response, 200, "upload")
            receipt = response.headers.get(config.upload_ack_header, "")
            if not re.fullmatch(r"[0-9]{1,10}", receipt):
                raise ProbeError("upload receipt missing or invalid")
            confirmed = int(receipt)
            if (
                confirmed != config.upload_bytes
                or observation.upload_bytes != config.upload_bytes
            ):
                raise ProbeError("incomplete upload receipt")
            if (
                response.headers.get("Content-Encoding", "identity").lower()
                != "identity"
            ):
                raise ProbeError("compressed upload response")
            await bounded_body(response, 4096)
        observation.upload_confirmed_bytes = confirmed
        observation.upload_ms = max(0.001, (time.monotonic() - started) * 1000)
        observation.upload_ok = True
    except (aiohttp.ClientError, TimeoutError, ProbeError) as error:
        failed("upload", error)


async def check_vpn(
    spec,
    config,
    core,
    geoip=None,
    *,
    preferred_ip=None,
    attempt=0,
    quick_retry=False,
    health_only=False,
):
    started = time.monotonic()
    observation = VPNObservation(
        samples=1 if health_only else config.samples,
        checker_version=CHECKER_VERSION,
        validation_key=config.validation_key,
        health_validation_key=config.health_validation_key,
        required_health_probes=len(config.health_probe_urls),
        check_kind="health" if health_only else "full",
    )
    phase = "dns"

    def set_phase(value):
        nonlocal phase
        phase = value

    try:
        async with asyncio.timeout(
            config.health_timeout_seconds
            if health_only
            else config.check_timeout_seconds
        ):
            dns_started = time.monotonic()
            async with asyncio.timeout(config.connect_timeout_seconds):
                addresses = await resolve_public(spec.host, spec.port)
            observation.dns_ms = (time.monotonic() - dns_started) * 1000
            addresses = sorted(addresses, key=lambda item: item[1] != preferred_ip)
            if attempt and len(addresses) > 1:
                offset = (attempt - 1) % len(addresses)
                addresses = addresses[offset:] + addresses[:offset]
            addresses = addresses[: 1 if quick_retry or health_only else 3]
            # Pin the validated IP, retaining the original TLS name and HTTP Host.
            # Trying a second DNS address must not double-count this check as a success.
            for _, address in addresses[:3]:
                observation.resolved_ip = address
                observation.endpoint_country_code = None
                phase = "tunnel"
                try:
                    if spec.protocol not in {"hysteria2", "tuic"}:
                        phase = "connect"
                        await tcp_preflight(
                            address, spec.port, min(2.5, config.connect_timeout_seconds)
                        )
                        phase = "tunnel"
                    options = (
                        {"timeout": config.health_timeout_seconds}
                        if health_only
                        else {}
                    )
                    async with core.tunnel(spec, address, **options) as (
                        proxy,
                        auth,
                        process,
                        audit,
                    ):
                        context = ssl.create_default_context()
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
                        connector = aiohttp.TCPConnector(ssl=context, limit=1)
                        async with aiohttp.ClientSession(
                            connector=connector, trust_env=False, auto_decompress=False
                        ) as session:

                            def check_local(error):
                                if (
                                    process.returncode is not None
                                    or isinstance(
                                        error, aiohttp.ClientProxyConnectionError
                                    )
                                    or getattr(error, "status", None) == 407
                                ):
                                    raise CoreError(
                                        "local sing-box inbound failed"
                                    ) from error
                                if audit is not None:
                                    if audit.local_error is not None:
                                        raise CoreError(
                                            "local TLS audit relay failed"
                                        ) from audit.local_error
                                    if audit.error is not None:
                                        raise audit.error from error

                            try:
                                await probe_tunnel(
                                    session,
                                    proxy,
                                    auth,
                                    config,
                                    observation,
                                    geoip,
                                    on_phase=set_phase,
                                    on_error=check_local,
                                    quick_retry=quick_retry,
                                    health_only=health_only,
                                )
                            except (
                                aiohttp.ClientError,
                                TimeoutError,
                                ProbeError,
                            ) as error:
                                if (
                                    process.returncode is not None
                                    or isinstance(
                                        error, aiohttp.ClientProxyConnectionError
                                    )
                                    or getattr(error, "status", None) == 407
                                ):
                                    raise CoreError(
                                        "local sing-box inbound failed"
                                    ) from error
                                if audit is not None:
                                    if audit.local_error is not None:
                                        raise CoreError(
                                            "local TLS audit relay failed"
                                        ) from audit.local_error
                                    if audit.error is not None:
                                        raise audit.error from error
                                raise
                            finally:
                                if audit is not None:
                                    observation.tls_sessions = list(
                                        audit.negotiations.values()
                                    )
                        if audit is not None:
                            if audit.local_error is not None:
                                raise CoreError(
                                    "local TLS audit relay failed"
                                ) from audit.local_error
                            if audit.error is not None:
                                raise audit.error
                            if observation.reachable and not audit.negotiations:
                                raise CoreError(
                                    "VPN TLS negotiation was not observed by the audit relay"
                                )
                        if process.returncode is not None:
                            raise CoreError("sing-box exited during the check")
                    if observation.reachable or address == addresses[:3][-1][1]:
                        break
                except (
                    TimeoutError,
                    aiohttp.ClientError,
                    ProbeError,
                    TLSAuditError,
                ) as error:
                    if (
                        unsafe_tls(error)
                        or observation.reachable
                        or address == addresses[:3][-1][1]
                    ):
                        raise
                if not observation.reachable:
                    observation = VPNObservation(
                        samples=observation.samples,
                        id=observation.id,
                        checked_at=observation.checked_at,
                        dns_ms=observation.dns_ms,
                        checker_version=CHECKER_VERSION,
                        validation_key=config.validation_key,
                        health_validation_key=config.health_validation_key,
                        required_health_probes=len(config.health_probe_urls),
                        check_kind="health" if health_only else "full",
                    )
    except (TimeoutError, aiohttp.ClientError, ProbeError, TLSAuditError) as error:
        # CoreError, programming errors, GeoIP/storage failures and cancellation propagate.
        if isinstance(error, TimeoutError) and phase == "tunnel":
            # A check can exhaust its budget while waiting for a local startup
            # slot, before the VPN makes any request. This is inconclusive.
            raise CoreError(
                "local sing-box startup exceeded the check budget"
            ) from error
        observation.error = error_label(phase, error)
        observation.stage_errors[phase] = observation.error
        observation.safety_error = unsafe_tls(error)
    except OSError as error:
        if phase != "dns":
            raise
        observation.error = f"dns: {type(error).__name__}"
    observation.duration_ms = (time.monotonic() - started) * 1000
    return observation
