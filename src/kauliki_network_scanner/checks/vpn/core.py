"""Bounded, staggered sing-box startup with redacted local diagnostics."""

import asyncio
import base64
from contextlib import AsyncExitStack, asynccontextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import tempfile

from kauliki_network_scanner.checks.vpn.tls_audit import TLSAuditRelay


class CoreError(RuntimeError):
    """Local measurement failure; never evidence that a VPN is dead."""


class CoreConfigError(CoreError):
    """This generated outbound is unsupported by the installed core."""


def checker_config(spec, address, port, config, username, password):
    outbound = deepcopy(spec.outbound)
    outbound.update(
        server=address, tag="vpn", connect_timeout=f"{config.connect_timeout_seconds}s"
    )
    stream = outbound.get("transport", {})
    if stream.get("type") == "ws":
        stream.setdefault("headers", {}).setdefault("Host", spec.host)
    elif stream.get("type") in {"http", "httpupgrade"}:
        stream.setdefault(
            "host", [spec.host] if stream["type"] == "http" else spec.host
        )
    return {
        "log": {"disabled": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "probe",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"username": username, "password": password}],
            }
        ],
        "outbounds": [outbound],
        "route": {"final": "vpn"},
    }


def core_detail(data, spec, username, password):
    message = data.decode(errors="replace")
    sensitive = {username, password, spec.uri}

    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {
                    "uuid",
                    "password",
                    "username",
                    "public_key",
                    "short_id",
                    "private_key",
                } and isinstance(item, str):
                    sensitive.add(item)
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(spec.outbound)
    for value in sorted((value for value in sensitive if value), key=len, reverse=True):
        message = message.replace(value, "[redacted]")
        message = message.replace(json.dumps(value)[1:-1], "[redacted]")
    message = re.sub(r"\x1b\[[0-9;]*m", "", message)
    message = re.sub(
        r"(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://\S+", "[vpn-uri]", message
    )
    message = re.sub(r"(?i)(Basic|Bearer) [A-Za-z0-9+/=_-]+", r"\1 [redacted]", message)
    return " ".join(message.split())[-250:]


async def terminate(process):
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            async with asyncio.timeout(3):
                await process.wait()
        except TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
    await process.wait()


class CoreRunner:
    def __init__(self, config):
        self.config = config
        self.binary = None
        self.startup_slots = asyncio.Semaphore(config.core_start_concurrency)
        self.validated = set()

    async def prepare(self):
        candidate = shutil.which(self.config.core_path)
        if candidate is None:
            path = Path(self.config.core_path)
            if path.is_file() and os.access(path, os.X_OK):
                candidate = str(path.resolve())
        if candidate is None:
            raise CoreError(
                "sing-box is missing; install the core or configure vpn.core_path"
            )
        process = await asyncio.create_subprocess_exec(
            candidate,
            "version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(self.config.core_start_timeout_seconds):
                output, _ = await process.communicate()
        finally:
            await terminate(process)
        version = re.search(rb"sing-box version (\d+)\.(\d+)\.(\d+)", output)
        if (
            process.returncode
            or not version
            or tuple(int(part) for part in version.groups()) < (1, 12, 0)
        ):
            raise CoreError("sing-box >= 1.12 is required")
        self.binary = candidate

    async def validate(self, path, spec, username, password):
        if spec.key in self.validated:
            return
        process = await asyncio.create_subprocess_exec(
            self.binary,
            "check",
            "-c",
            str(path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        diagnostic = bytearray()

        async def drain():
            while block := await process.stderr.read(4096):
                diagnostic.extend(block)
                del diagnostic[:-4096]

        reader = asyncio.create_task(drain())
        try:
            async with asyncio.timeout(self.config.core_start_timeout_seconds):
                await process.wait()
                await reader
            if process.returncode < 0:
                raise CoreError(
                    f"sing-box config validation was killed; code={process.returncode}"
                )
            if process.returncode:
                raise CoreConfigError(
                    "sing-box config rejected: "
                    + core_detail(diagnostic, spec, username, password)
                )
            if len(self.validated) >= 1000:
                self.validated.clear()
            self.validated.add(spec.key)
        except TimeoutError as error:
            raise CoreError("sing-box config validation timed out") from error
        finally:
            await terminate(process)
            await reader

    @asynccontextmanager
    async def tunnel(self, spec, address, *, timeout=None):
        if self.binary is None:
            raise CoreError("sing-box was not prepared")
        async with AsyncExitStack() as resources:
            audit = None
            if spec.protocol in {"vless", "vmess", "trojan"}:
                minimum = (
                    0x0304 if spec.outbound["tls"]["min_version"] == "1.3" else 0x0303
                )
                audit = await resources.enter_async_context(
                    TLSAuditRelay(
                        address,
                        spec.port,
                        minimum,
                        timeout or self.config.check_timeout_seconds,
                    )
                )
            async with self._core_tunnel(spec, address, audit) as value:
                yield value

    @asynccontextmanager
    async def _core_tunnel(self, spec, address, audit):
        username, password = secrets.token_hex(8), secrets.token_hex(24)
        process = drain = None
        diagnostic = bytearray()
        with tempfile.TemporaryDirectory(prefix="network-scanner-vpn-") as directory:
            try:
                async with self.startup_slots:
                    with socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM
                    ) as reservation:
                        reservation.bind(("127.0.0.1", 0))
                        port = reservation.getsockname()[1]
                        path = Path(directory) / "config.json"
                        settings = checker_config(
                            spec, address, port, self.config, username, password
                        )
                        if audit is not None:
                            settings["outbounds"][0]["detour"] = "tls-audit"
                            settings["outbounds"].append(audit.outbound())
                        path.write_text(json.dumps(settings))
                        path.chmod(0o600)
                        await self.validate(path, spec, username, password)
                    process = await asyncio.create_subprocess_exec(
                        self.binary,
                        "run",
                        "-c",
                        str(path),
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.PIPE,
                    )

                    async def drain_errors():
                        while block := await process.stderr.read(4096):
                            diagnostic.extend(block)
                            del diagnostic[:-4096]

                    drain = asyncio.create_task(drain_errors())
                    try:
                        async with asyncio.timeout(
                            self.config.core_start_timeout_seconds
                        ):
                            while True:
                                if process.returncode is not None:
                                    await drain
                                    raise CoreError(
                                        f"sing-box exited before opening its local inbound; code={process.returncode}; "
                                        + core_detail(
                                            diagnostic, spec, username, password
                                        )
                                    )
                                try:
                                    _, writer = await asyncio.open_connection(
                                        "127.0.0.1", port
                                    )
                                except (ConnectionRefusedError, ConnectionResetError):
                                    await asyncio.sleep(0.05)
                                    continue
                                writer.close()
                                await writer.wait_closed()
                                break
                    except TimeoutError as error:
                        raise CoreError(
                            "sing-box local inbound did not start"
                        ) from error
                authorization = (
                    "Basic "
                    + base64.b64encode(f"{username}:{password}".encode()).decode()
                )
                yield (
                    f"http://127.0.0.1:{port}",
                    {"Proxy-Authorization": authorization},
                    process,
                    audit,
                )
            except TimeoutError as error:
                if process is not None and process.returncode is not None:
                    raise CoreError(
                        f"sing-box exited during the check; code={process.returncode}"
                    ) from error
                raise
            finally:
                if process is not None:
                    await terminate(process)
                if drain is not None:
                    await drain
