"""HTTPS only; no redirects, environment proxies, SSH or database access."""

import json
import time
import math

import aiohttp


ERROR_CODES = frozenset(
    """
unauthorized scanner_disabled rate_limited busy temporarily_unavailable request_timeout
invalid_request json_required body_too_large invalid_content_length not_found invalid_peer
kind_forbidden heartbeat_required request_id_conflict observation_too_large
invalid_observation_shape observation_identity_required invalid_observation policy_mismatch
samples_mismatch attempt_limit measurement_outside_lease expired_result endpoint_mismatch
incomplete_transfer_proof health_providers_mismatch dc_mismatch assignment_not_owned
observation_id_conflict assignment_completed attempt_conflict
""".split()
)


def safe_code(value, default="api_rejected"):
    return value if isinstance(value, str) and value in ERROR_CODES else default


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
                "User-Agent": "sauh_network_scanner/1.0.0",
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
                        delay = min(60, max(1, float(response.headers.get("Retry-After", 5))))
                    except ValueError:
                        delay = 5
                    if not math.isfinite(delay):
                        delay = 5
                    fallback = {
                        401: "unauthorized",
                        403: "unauthorized",
                        429: "rate_limited",
                        502: "bad_gateway",
                        503: "temporarily_unavailable",
                        504: "gateway_timeout",
                    }.get(response.status, "api_rejected")
                    try:
                        payload = json.loads(raw)
                        code = (
                            safe_code(payload.get("error"), fallback)
                            if isinstance(payload, dict)
                            else fallback
                        )
                    except ValueError:
                        code = fallback
                    # Only known protocol codes are logged; never arbitrary bodies.
                    raise APIError(
                        response.status,
                        code,
                        delay,
                    )
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise APIError(200, "invalid_response")
                if result.get("server_time"):
                    from datetime import datetime

                    server = datetime.fromisoformat(result["server_time"]).timestamp()
                    self.clock_offset = server - (started + time.time()) / 2
                    self.server_epoch = server + (time.monotonic() - started_monotonic) / 2
                    self.server_monotonic = time.monotonic()
                return result
        except APIError:
            raise
        except TimeoutError:
            raise APIError(code="connection_timeout") from None
        except (aiohttp.ClientError, OSError):
            raise APIError() from None
        except ValueError:
            raise APIError(200, "invalid_response") from None
