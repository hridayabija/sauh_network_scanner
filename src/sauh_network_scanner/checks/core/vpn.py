"""VPN settings usable by maintenance commands without loading bot credentials."""

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator, model_validator

from sauh_network_scanner.checks.core.geoip import DEFAULT_GEOIP_PATH, GeoIPMode
from sauh_network_scanner.checks.core.proxy import ProxyURL


def web_url(value: str, *, https_only=True):
    parts = urlsplit(value)
    if (
        parts.scheme not in ({"https"} if https_only else {"http", "https"})
        or not parts.hostname
    ):
        raise ValueError(
            "a valid HTTPS URL is required"
            if https_only
            else "a valid HTTP(S) URL is required"
        )
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError("URL credentials and fragments are not supported")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise ValueError("invalid URL port")
    return value


SourceURL = Annotated[str, Field(max_length=2048, strict=True)]


SourcesProxy = ProxyURL
DEFAULT_PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.youtube.com/generate_204",
]


@dataclass(frozen=True)
class VPNSourceEndpoint:
    name: str
    url: str
    enabled: bool


class VPNSourceSettings(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
    url: SourceURL | Annotated[list[SourceURL], Field(min_length=1, max_length=100)]
    enabled: bool = Field(default=True, strict=True)

    @field_validator("url")
    @classmethod
    def source_url(cls, value):
        if isinstance(value, str):
            return web_url(value)
        return list(dict.fromkeys(web_url(url) for url in value))

    @property
    def endpoints(self):
        urls = [self.url] if isinstance(self.url, str) else self.url
        result = []
        for index, url in enumerate(urls):
            # Keep the existing source row for the first URL. Other URLs have
            # independent snapshots and HTTP validators, with keys fitting the DB.
            digest = hashlib.sha256(f"{self.name}\0{url}".encode()).hexdigest()[:32]
            name = self.name if index == 0 else f"{self.name[:31]}:{digest}"
            result.append(VPNSourceEndpoint(name, url, self.enabled))
        return result


class VPNHTTPSettings(BaseModel):
    model_config = {"extra": "forbid"}
    enabled: bool = Field(default=False, strict=True)
    host: str = "0.0.0.0"
    port: int = Field(default=8927, ge=1, le=65535, strict=True)
    public_base_url: str | None = None
    max_servers: int = Field(default=100, ge=1, le=1000, strict=True)
    concurrency: int = Field(default=20, ge=1, le=200, strict=True)
    database_timeout_seconds: float = Field(
        default=10, gt=0, le=60, allow_inf_nan=False
    )

    @field_validator("public_base_url")
    @classmethod
    def public_url(cls, value):
        if value is None:
            return None
        value = web_url(value, https_only=False).rstrip("/")
        parts = urlsplit(value)
        if (
            parts.query
            or parts.path not in {"", "/"}
            or parts.hostname in {"0.0.0.0", "::"}
        ):
            raise ValueError(
                "public_base_url must be an externally reachable origin without a path or query"
            )
        return value


class VPNSettings(BaseModel):
    model_config = {"extra": "forbid", "hide_input_in_errors": True}
    enabled: bool = Field(default=False, strict=True)
    refresh_enabled: bool = Field(default=False, strict=True)
    check_enabled: bool = Field(default=False, strict=True)
    refresh_interval_hours: float = Field(default=1, gt=0, allow_inf_nan=False)
    interval_hours: float = Field(default=2, gt=0, allow_inf_nan=False)
    # Full quality evidence expires independently of the live health snapshot.
    max_age_hours: float = Field(default=6, gt=0, allow_inf_nan=False)
    source_stale_hours: float = Field(default=24, gt=0, allow_inf_nan=False)
    sources: list[VPNSourceSettings] = Field(default_factory=list, max_length=100)
    sources_proxy: SourcesProxy | None = None
    source_concurrency: int = Field(default=3, ge=1, le=20, strict=True)
    source_timeout_seconds: float = Field(default=30, gt=0, le=180, allow_inf_nan=False)
    max_source_bytes: int = Field(
        default=8 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024, strict=True
    )
    max_nodes_per_source: int = Field(default=10000, ge=1, le=100000, strict=True)
    max_checks_per_pass: int = Field(default=10000, ge=1, le=100000, strict=True)
    concurrency: int = Field(default=10, ge=1, le=100, strict=True)
    core_path: str = "storage/vpn/bin/sing-box"
    core_start_timeout_seconds: float = Field(
        default=10, gt=0, le=60, allow_inf_nan=False
    )
    core_start_concurrency: int = Field(default=2, ge=1, le=100, strict=True)
    connect_timeout_seconds: float = Field(default=4, gt=0, le=60, allow_inf_nan=False)
    probe_timeout_seconds: float = Field(default=3, gt=0, le=60, allow_inf_nan=False)
    trace_timeout_seconds: float = Field(default=5, gt=0, le=60, allow_inf_nan=False)
    download_timeout_seconds: float = Field(
        default=30, gt=0, le=120, allow_inf_nan=False
    )
    upload_timeout_seconds: float = Field(default=30, gt=0, le=120, allow_inf_nan=False)
    check_timeout_seconds: float = Field(default=120, gt=0, le=300, allow_inf_nan=False)
    recheck_attempts: int = Field(default=2, ge=0, le=3, strict=True)
    health_recheck_attempts: int | None = Field(default=None, ge=0, le=3, strict=True)
    full_check_batch_size: int = Field(default=200, ge=1, le=200, strict=True)
    health_check_batch_size: int = Field(default=200, ge=1, le=200, strict=True)
    # Compatibility with older YAML; retries use the same bounded workers.
    recheck_concurrency: int | None = Field(default=None, ge=1, le=100, strict=True)
    recheck_delay_seconds: float = Field(default=1, ge=0, le=30, allow_inf_nan=False)
    retention_hours: float = Field(default=48, gt=0, le=48, allow_inf_nan=False)
    cleanup_batch_size: int = Field(default=2000, ge=1, le=10000, strict=True)
    cleanup_interval_seconds: float = Field(
        default=60, gt=0, le=3600, allow_inf_nan=False
    )
    retired_retry_hours: float = Field(default=48, gt=0, le=168, allow_inf_nan=False)
    retired_history_hours: float = Field(
        default=168, ge=168, le=720, allow_inf_nan=False
    )
    max_unvalidated_nodes: int = Field(default=10000, ge=1, le=100000, strict=True)
    max_unvalidated_nodes_per_source: int = Field(
        default=1000, ge=1, le=100000, strict=True
    )
    source_candidate_limits: dict[
        SourceURL, Annotated[int, Field(ge=1, le=100000, strict=True)]
    ] = Field(default_factory=dict)

    @field_validator("source_candidate_limits")
    @classmethod
    def validate_candidate_limit_urls(cls, value):
        return {web_url(url): limit for url, limit in value.items()}

    health_workers: int = Field(default=3, ge=1, le=100, strict=True)
    health_pool_size: int = Field(default=150, ge=1, le=2000, strict=True)
    health_interval_seconds: float = Field(
        default=180, gt=0, le=3600, allow_inf_nan=False
    )
    health_max_age_seconds: float = Field(
        default=900, gt=0, le=21600, allow_inf_nan=False
    )
    health_timeout_seconds: float = Field(default=15, gt=0, le=60, allow_inf_nan=False)
    full_check_interval_seconds: float = Field(
        default=1800, gt=0, le=86400, allow_inf_nan=False
    )
    admission_check_interval_seconds: float = Field(
        default=120, gt=0, le=3600, allow_inf_nan=False
    )
    failed_check_interval_seconds: float = Field(
        default=600, gt=0, le=86400, allow_inf_nan=False
    )
    max_failure_backoff_seconds: float = Field(
        default=21600, gt=0, le=172800, allow_inf_nan=False
    )
    checker_error_retry_seconds: float = Field(
        default=60, gt=0, le=3600, allow_inf_nan=False
    )
    samples: int = Field(default=2, ge=1, le=10, strict=True)
    sample_delay_seconds: float = Field(default=0.25, ge=0, le=10, allow_inf_nan=False)
    probe_url: (
        SourceURL | Annotated[list[SourceURL], Field(min_length=1, max_length=10)]
    ) = Field(default_factory=lambda: list(DEFAULT_PROBE_URLS))
    trace_url: str = "https://www.cloudflare.com/cdn-cgi/trace"
    download_url: str = "http://cachefly.cachefly.net/1mb.test"
    download_bytes: int = Field(default=1048576, ge=65536, le=4194304, strict=True)
    upload_url: str = "https://speed.cloudflare.com/__up"
    upload_bytes: int = Field(default=1048576, ge=65536, le=4194304, strict=True)
    upload_ack_header: str = Field(
        default="cf-meta-upload-bytes", pattern=r"^[A-Za-z0-9-]{1,128}$"
    )
    min_successful_checks: int = Field(default=3, ge=1, le=20, strict=True)
    min_stability_score: float = Field(default=35, ge=0, le=100, allow_inf_nan=False)
    export_min_successful_checks: int | None = Field(
        default=None, ge=1, le=100000, strict=True
    )
    export_min_stability_score: float | None = Field(
        default=None, ge=0, le=100, allow_inf_nan=False
    )
    export_min_consecutive_successes: int = Field(default=0, ge=0, le=20, strict=True)
    export_max_health_age_seconds: float | None = Field(
        default=None, gt=0, le=21600, allow_inf_nan=False
    )
    export_max_full_age_hours: float | None = Field(
        default=None, gt=0, le=48, allow_inf_nan=False
    )
    export_require_healthy: bool = Field(default=False, strict=True)
    export_require_latest_full_success: bool = Field(default=False, strict=True)
    export_require_matching_ip: bool = Field(default=False, strict=True)
    export_prefer_stability: bool = Field(default=False, strict=True)
    export_pin_server_ip: bool = Field(default=False, strict=True)
    export_exclude_dpi_failure: bool = Field(default=False, strict=True)
    min_ru_dpi_rating: float = Field(default=0, ge=0, le=100, allow_inf_nan=False)
    ru_dpi_max_age_hours: float = Field(default=6, gt=0, le=24, allow_inf_nan=False)
    max_latency_ms: float = Field(default=1500, gt=0, allow_inf_nan=False)
    max_first_response_ms: float = Field(default=3000, gt=0, allow_inf_nan=False)
    min_download_mbps: float = Field(default=1, gt=0, allow_inf_nan=False)
    min_upload_mbps: float = Field(default=0.5, gt=0, allow_inf_nan=False)
    geoip_path: str | None = DEFAULT_GEOIP_PATH
    geoip_mode: GeoIPMode = "file"
    http: VPNHTTPSettings = Field(default_factory=VPNHTTPSettings)

    @property
    def source_endpoints(self):
        return [endpoint for source in self.sources for endpoint in source.endpoints]

    @property
    def probe_urls(self):
        return [self.probe_url] if isinstance(self.probe_url, str) else self.probe_url

    @property
    def validation_key(self):
        values = dict(
            probe_urls=sorted(self.probe_urls),
            samples=self.samples,
            trace_url=self.trace_url,
            download_url=self.download_url,
            download_bytes=self.download_bytes,
            upload_url=self.upload_url,
            upload_bytes=self.upload_bytes,
            upload_ack_header=self.upload_ack_header,
        )
        return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()

    @property
    def health_probe_urls(self):
        from sauh_network_scanner.checks.domain.vpn import probe_provider

        result, providers = [], set()
        for url in self.probe_urls:
            provider = probe_provider(url)
            if provider not in providers:
                providers.add(provider)
                result.append(url)
        return result[:2]

    @property
    def health_validation_key(self):
        values = dict(
            validation_key=self.validation_key,
            urls=self.health_probe_urls,
            required=len(self.health_probe_urls),
            checker_version=4,
        )
        return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()

    @field_validator("probe_url")
    @classmethod
    def probe_addresses(cls, value):
        if isinstance(value, str):
            return web_url(value)
        return list(dict.fromkeys(web_url(url) for url in value))

    @field_validator("trace_url", "upload_url", "download_url")
    @classmethod
    def check_url(cls, value, info):
        if "{" in value.replace("{bytes}", "") or "}" in value.replace("{bytes}", ""):
            raise ValueError("only the {bytes} placeholder is supported")
        return web_url(value, https_only=info.field_name != "download_url")

    @model_validator(mode="after")
    def unique_sources(self):
        if len({source.name for source in self.sources}) != len(self.sources):
            raise ValueError("source names must be unique")
        if self.source_stale_hours < self.refresh_interval_hours:
            raise ValueError("source_stale_hours must cover the refresh interval")
        if self.health_max_age_seconds < self.health_interval_seconds:
            raise ValueError("health_max_age_seconds must cover the health interval")
        if (
            self.export_max_health_age_seconds is not None
            and self.export_max_health_age_seconds < self.health_interval_seconds
        ):
            raise ValueError(
                "export_max_health_age_seconds must cover the health interval"
            )
        if self.max_failure_backoff_seconds < self.failed_check_interval_seconds:
            raise ValueError(
                "max_failure_backoff_seconds must cover the initial failure interval"
            )
        return self
