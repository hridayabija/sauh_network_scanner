"""Standalone checker settings; importing this module never loads bot credentials."""

import hashlib
import json

from pydantic import BaseModel, Field, field_validator, model_validator

from kauliki_network_scanner.checks.core.geoip import DEFAULT_GEOIP_PATH, GeoIPMode
from kauliki_network_scanner.checks.core.vpn import SourcesProxy, VPNSourceSettings
from kauliki_network_scanner.checks.domain.mtproxy import PROXY_TYPE_KINDS, ProxyType


class MTProxySettings(BaseModel):
    model_config = {"extra": "forbid", "hide_input_in_errors": True}

    enabled: bool = Field(default=False, strict=True)
    proxy_types: list[ProxyType] = Field(
        default_factory=lambda: ["ee"], min_length=1, max_length=3, strict=True
    )
    refresh_enabled: bool = Field(default=False, strict=True)
    check_enabled: bool = Field(default=False, strict=True)
    refresh_interval_hours: float = Field(default=1, gt=0, allow_inf_nan=False)
    interval_hours: float = Field(default=2, gt=0, allow_inf_nan=False)
    concurrency: int = Field(default=5, ge=1, le=100, strict=True)
    health_workers: int = Field(default=1, ge=1, le=100, strict=True)
    health_pool_size: int = Field(default=90, ge=1, le=1000, strict=True)
    health_interval_seconds: float = Field(
        default=120, gt=0, le=3600, allow_inf_nan=False
    )
    health_max_age_seconds: float = Field(
        default=300, gt=0, le=3600, allow_inf_nan=False
    )
    health_timeout_seconds: float = Field(default=12, gt=0, le=60, allow_inf_nan=False)
    check_timeout_seconds: float = Field(default=60, gt=0, le=300, allow_inf_nan=False)
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
    recheck_attempts: int = Field(default=1, ge=0, le=3, strict=True)
    recheck_delay_seconds: float = Field(default=0.5, ge=0, le=30, allow_inf_nan=False)
    connect_timeout_seconds: float = Field(default=4, gt=0, le=60, allow_inf_nan=False)
    probe_timeout_seconds: float = Field(default=15, gt=0, le=180, allow_inf_nan=False)
    samples: int = Field(default=3, ge=1, le=10, strict=True)
    sample_delay_seconds: float = Field(default=0.25, ge=0, le=10, allow_inf_nan=False)
    dc_ids: list[int] = Field(
        default_factory=lambda: [1, 2, 3, 4, 5], min_length=1, max_length=5
    )
    max_age_hours: float = Field(default=6, gt=0, allow_inf_nan=False)
    min_successful_checks: int = Field(default=3, ge=1, le=20, strict=True)
    min_stability_score: float = Field(default=35, ge=0, le=100, allow_inf_nan=False)
    min_ru_dpi_rating: float = Field(default=0, ge=0, le=100, allow_inf_nan=False)
    ru_dpi_max_age_hours: float = Field(default=6, gt=0, le=24, allow_inf_nan=False)
    max_latency_ms: float = Field(default=1500, gt=0, allow_inf_nan=False)
    max_first_response_ms: float = Field(default=3000, gt=0, allow_inf_nan=False)
    max_proxies: int = Field(default=30, ge=1, le=100, strict=True)
    max_checks_per_pass: int = Field(default=10000, ge=1, le=100000, strict=True)
    geoip_path: str | None = DEFAULT_GEOIP_PATH
    geoip_mode: GeoIPMode = "file"
    sources: list[VPNSourceSettings] = Field(default_factory=list, max_length=100)
    sources_proxy: SourcesProxy | None = None
    source_concurrency: int = Field(default=3, ge=1, le=20, strict=True)
    source_timeout_seconds: float = Field(default=30, gt=0, le=180, allow_inf_nan=False)
    max_source_bytes: int = Field(
        default=8 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024, strict=True
    )
    max_proxies_per_source: int = Field(default=100000, ge=1, le=100000, strict=True)

    @property
    def source_endpoints(self):
        return [endpoint for source in self.sources for endpoint in source.endpoints]

    @property
    def proxy_kinds(self):
        return tuple(PROXY_TYPE_KINDS[value] for value in self.proxy_types)

    @property
    def validation_key(self):
        values = dict(dc_ids=sorted(self.dc_ids), samples=self.samples)
        return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()

    @property
    def health_validation_key(self):
        values = dict(
            validation_key=self.validation_key,
            dc_ids=sorted(self.dc_ids),
            samples=1,
            checker_version=4,
        )
        return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()

    @model_validator(mode="after")
    def unique_sources(self):
        if len({source.name for source in self.sources}) != len(self.sources):
            raise ValueError("source names must be unique")
        if self.health_max_age_seconds < self.health_interval_seconds:
            raise ValueError("health_max_age_seconds must cover the health interval")
        if self.max_failure_backoff_seconds < self.failed_check_interval_seconds:
            raise ValueError(
                "max_failure_backoff_seconds must cover the initial failure interval"
            )
        return self

    @field_validator("dc_ids")
    @classmethod
    def validate_dcs(cls, value):
        if len(set(value)) != len(value) or any(dc not in range(1, 6) for dc in value):
            raise ValueError("dc_ids must contain unique Telegram DC IDs 1–5")
        return value

    @field_validator("proxy_types")
    @classmethod
    def unique_proxy_types(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("proxy_types must contain unique values: default, ee, dd")
        return value
