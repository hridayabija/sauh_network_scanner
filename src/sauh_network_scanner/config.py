"""Device-local limits and its own API credential, without bot/server settings."""

from datetime import datetime
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, model_validator
import yaml


class Settings(BaseModel):
    model_config = {"extra": "forbid", "hide_input_in_errors": True}
    api_url: str = "https://sauh.duckdns.org"
    API_KEY: SecretStr | None = None
    API_KEY_ENV: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]*$")
    API_KEY_FILE: str = "credentials.json"
    state_directory: str = "state"
    core_path: str = "state/bin/sing-box"
    vpn_full_workers: int = Field(default=2, ge=0, le=32, strict=True)
    vpn_health_workers: int = Field(default=2, ge=0, le=32, strict=True)
    mtproxy_full_workers: int = Field(default=1, ge=0, le=32, strict=True)
    mtproxy_health_workers: int = Field(default=1, ge=0, le=32, strict=True)
    core_start_concurrency: int = Field(default=2, ge=1, le=8)
    heartbeat_seconds: float = Field(default=30, ge=5, le=120)
    poll_seconds: float = Field(default=5, ge=0.1, le=60)
    publish_seconds: float = Field(default=2, ge=0.1, le=60)
    publish_batch_size: int = Field(default=100, ge=1, le=100)
    max_pending_results: int = Field(default=2000, ge=100, le=100000)
    max_storage_mb: int = Field(default=256, ge=16, le=4096)
    request_timeout_seconds: float = Field(default=20, ge=1, le=120)
    retry_max_seconds: float = Field(default=60, ge=1, le=300)
    pause_on_battery: bool = False
    active_hours: list[str] | None = Field(default=None, min_length=2, max_length=2)
    active_days: list[int] = Field(
        default_factory=lambda: list(range(7)), min_length=1, max_length=7
    )
    allow_http_loopback: bool = False

    @model_validator(mode="after")
    def validate_local_settings(self):
        parsed = urlsplit(self.api_url)
        loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and loopback and self.allow_http_loopback
        ):
            raise ValueError(
                "api_url must use HTTPS; local HTTP tests require allow_http_loopback"
            )
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path.strip("/")
        ):
            raise ValueError(
                "api_url must contain only an origin, without credentials/path/query"
            )
        if any(day not in range(7) for day in self.active_days) or len(
            set(self.active_days)
        ) != len(self.active_days):
            raise ValueError("active_days must contain unique weekdays 0..6")
        if self.active_hours and any(
            not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value)
            for value in self.active_hours
        ):
            raise ValueError("active_hours must contain two HH:MM times")
        if (
            sum(
                self.workers(kind, phase)
                for kind in ("vpn", "mtproxy")
                for phase in ("full", "health")
            )
            > 64
        ):
            raise ValueError("total local worker limit is 64")
        return self

    def workers(self, kind, phase):
        return getattr(self, f"{kind}_{phase}_workers")

    def credential(self):
        if self.API_KEY:
            key = self.API_KEY.get_secret_value()
        elif self.API_KEY_ENV:
            key = os.environ.get(self.API_KEY_ENV, "")
        else:
            try:
                key = json.loads(Path(self.API_KEY_FILE).read_text())["API_KEY"]
            except (OSError, ValueError, KeyError):
                raise ValueError(
                    "Configure your own API_KEY with the configure command"
                ) from None
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._-]{32,512}", key):
            raise ValueError("Your API_KEY must contain at least 32 characters")
        return key

    def scheduled(self, now=None):
        now = now or datetime.now()
        if now.weekday() not in self.active_days:
            return False
        if not self.active_hours:
            return True
        start, end = self.active_hours
        clock = now.strftime("%H:%M")
        return start <= clock < end if start < end else clock >= start or clock < end


def load_settings(path):
    path = Path(path).expanduser().resolve()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        settings = Settings.model_validate(data)
    except (ValueError, yaml.YAMLError):
        raise ValueError(
            "Invalid scanner configuration; sensitive values are not printed"
        ) from None
    for field in ("API_KEY_FILE", "state_directory", "core_path"):
        value = Path(getattr(settings, field)).expanduser()
        if not value.is_absolute():
            value = path.parent / value
        setattr(settings, field, str(value.resolve()))
    if os.name == "nt" and Path(settings.core_path).name == "sing-box":
        settings.core_path += ".exe"
    return settings
