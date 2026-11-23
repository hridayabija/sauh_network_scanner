"""HTTPS only; no redirects, environment proxies, SSH or database access."""

import json
import time

import aiohttp


class APIError(RuntimeError):
    def __init__(self, status=0, code="connection_failed", retry_after=5):
        self.status, self.code, self.retry_after = status, code, retry_after
        super().__init__(code)


class APIClient:
    def __init__(self, settings):
        self.settings = settings
        self.session = None
        self.clock_offset = 0
        self.server_epoch = time.time()
        self.server_monotonic = time.monotonic()

    def server_now(self):
        return self.server_epoch + time.monotonic() - self.server_monotonic

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            trust_env=False,
            auto_decompress=False,
            timeout=aiohttp.ClientTimeout(total=self.settings.request_timeout_seconds),
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": "kauliki_network_scanner/1.0.0",
            },
        )
        return self

    async def __aexit__(self, *args):
        await self.session.close()

    async def post(self, route, body):
        started = time.time()
        started_monotonic = time.monotonic()
        try:
            async with self.session.post(
                self.settings.api_url.rstrip("/") + "/v1/scanner/" + route,
                json=body,
                headers={"Authorization": "Bearer " + self.settings.credential()},
                allow_redirects=False,
            ) as response:
                raw = bytearray()
                if response.headers.get("Content-Encoding", "identity") != "identity":
                    raise APIError(response.status, "unexpected_content_encoding")
                async for block in response.content.iter_chunked(65536):
                    raw.extend(block)
                    if len(raw) > 2 * 1024 * 1024:
                        raise APIError(response.status, "response_too_large")
                if response.status != 200:
                    try:
                        delay = min(
                            60, max(1, float(response.headers.get("Retry-After", 5)))
                        )
                    except ValueError:
                        delay = 5
                    # Never use server bodies/exception URLs as log messages.
                    raise APIError(
                        response.status,
                        "unauthorized"
                        if response.status in (401, 403)
                        else "api_rejected",
                        delay,
                    )
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise APIError(200, "invalid_response")
                if result.get("server_time"):
                    from datetime import datetime

                    server = datetime.fromisoformat(result["server_time"]).timestamp()
                    self.clock_offset = server - (started + time.time()) / 2
                    self.server_epoch = (
                        server + (time.monotonic() - started_monotonic) / 2
                    )
                    self.server_monotonic = time.monotonic()
                return result
        except APIError:
            raise
        except (aiohttp.ClientError, TimeoutError, ValueError, OSError):
            raise APIError() from None
