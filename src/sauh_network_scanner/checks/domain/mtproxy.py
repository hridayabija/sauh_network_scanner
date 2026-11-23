"""MTProxy identities, immutable observations and reproducible ratings."""

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import math
import re
from statistics import median
from typing import Literal
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


TYPE_LABELS = {"normal": "Обычный", "faketls": "FakeTLS", "secure": "Secure Mode"}
ProxyType = Literal["default", "ee", "dd"]
PROXY_TYPE_KINDS = {"default": "normal", "ee": "faketls", "dd": "secure"}
HISTORY_WINDOW = 20
CHECKER_VERSION = 4
MIN_VALIDATED_CHECKER_VERSION = 2


def normalize_host(value: str) -> str:
    value = value.strip().removeprefix("[").removesuffix("]").rstrip(".")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.encode("idna").decode("ascii").lower()
    if (
        len(value) > 253
        or "." not in value
        or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        )
    ):
        raise ValueError("invalid server hostname")
    return value


@dataclass(frozen=True)
class ProxySecret:
    encoded: str
    key: bytes
    kind: str
    sni: str | None = None

    @classmethod
    def parse(cls, value: str):
        value = value.strip()
        if not value or len(value) > 1024:
            raise ValueError("invalid secret length")
        try:
            if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
                raw = bytes.fromhex(value)
            else:
                raw = base64.b64decode(
                    value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
                )
        except ValueError:
            raise ValueError("invalid hex/base64 secret") from None
        # A prefix is meaningful only AFTER decoding and checking the length.
        if len(raw) == 16:
            return cls(raw.hex(), raw, "normal")
        if len(raw) == 17 and raw[0] == 0xDD:
            return cls(raw.hex(), raw[1:], "secure")
        if len(raw) > 17 and raw[0] == 0xEE:
            try:
                sni = raw[17:].decode("ascii")
            except UnicodeError:
                raise ValueError("invalid FakeTLS SNI") from None
            normalized = normalize_host(sni)
            try:
                ipaddress.ip_address(normalized)
            except ValueError:
                return cls(raw.hex(), raw[1:17], "faketls", sni)
            raise ValueError("FakeTLS SNI must be a DNS name")
        raise ValueError("unsupported secret type or length")


@dataclass(frozen=True)
class ProxySpec:
    host: str
    port: int
    secret: str

    @classmethod
    def make(cls, host, port, secret):
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError("invalid proxy port")
        return cls(normalize_host(host), port, ProxySecret.parse(secret).encoded)

    @classmethod
    def from_url(cls, url):
        parts = urlsplit(url)
        if not (
            (
                parts.scheme in {"https", "http"}
                and parts.netloc.lower() in {"t.me", "telegram.me"}
                and parts.path.rstrip("/") == "/proxy"
            )
            or (parts.scheme == "tg" and parts.netloc == "proxy")
        ):
            raise ValueError("not an MTProxy link")
        values = parse_qs(parts.query)
        if any(len(values.get(key, [])) != 1 for key in ("server", "port", "secret")):
            raise ValueError("missing or duplicate proxy URL fields")
        # '+' is allowed in legacy base64 secrets; query parsers turn it into a space.
        return cls.make(
            values["server"][0],
            values["port"][0],
            values["secret"][0].replace(" ", "+"),
        )

    @property
    def key(self):
        return hashlib.sha256(
            f"{self.host}\n{self.port}\n{self.secret}".encode()
        ).hexdigest()

    @property
    def kind(self):
        return ProxySecret.parse(self.secret).kind

    @property
    def address(self):
        return (
            f"[{self.host}]:{self.port}"
            if ":" in self.host
            else f"{self.host}:{self.port}"
        )

    @property
    def url(self):
        return "https://t.me/proxy?" + urlencode(
            {"server": self.host, "port": self.port, "secret": self.secret}
        )


class DCObservation(BaseModel):
    model_config = {"extra": "forbid"}
    dc_id: int = Field(ge=1, le=5)
    ip: str | None = None
    tcp_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    handshake_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    handshake_ok: bool = False
    first_response_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    rtt_ms: list[float] = Field(default_factory=list, max_length=10)
    error: str | None = Field(default=None, max_length=300)

    @field_validator("rtt_ms")
    @classmethod
    def valid_timings(cls, value):
        if any(not math.isfinite(item) or item < 0 for item in value):
            raise ValueError("invalid RTT")
        return value


class ProxyObservation(BaseModel):
    model_config = {"extra": "forbid"}
    # Missing in legacy observations: version 1 had a resPQ padding rejection bug.
    checker_version: int = Field(default=1, ge=1)
    validation_key: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    health_validation_key: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    round_id: UUID | None = None
    check_kind: Literal["full", "health"] = "full"
    final: bool = True
    checker_error: bool = False
    attempt_count: int = Field(default=1, ge=1, le=4)
    attempt_errors: list[str] = Field(default_factory=list, max_length=4)
    id: UUID = Field(default_factory=uuid4)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    samples: int = Field(ge=1, le=10)
    country_code: str | None = None
    dns_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    duration_ms: float = Field(default=0, ge=0, allow_inf_nan=False)
    dcs: list[DCObservation] = Field(min_length=1, max_length=5)

    @field_validator("checked_at")
    @classmethod
    def aware_timestamp(cls, value):
        if value.tzinfo is None:
            raise ValueError("checked_at must have a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("country_code")
    @classmethod
    def country(cls, value):
        if value is not None and not re.fullmatch("[A-Z]{2}", value):
            raise ValueError("country_code must be an ISO alpha-2 code")
        return value

    @field_validator("dcs")
    @classmethod
    def unique_dcs(cls, value):
        if len({dc.dc_id for dc in value}) != len(value):
            raise ValueError("duplicate DC observations")
        return value

    @property
    def working(self):
        return (
            not self.checker_error
            and len({dc.ip for dc in self.dcs}) == 1
            and all(
                dc.ip
                and dc.handshake_ok
                and len(dc.rtt_ms) == self.samples
                and dc.error is None
                and dc.first_response_ms is not None
                for dc in self.dcs
            )
        )

    @property
    def reachable(self):
        return not self.checker_error and any(
            dc.handshake_ok and dc.rtt_ms for dc in self.dcs
        )

    @property
    def quality_round(self):
        return self.check_kind == "full" and self.final and not self.checker_error

    def matches_policy(self, config):
        if (
            self.check_kind != "full"
            or self.checker_error
            or self.checker_version < MIN_VALIDATED_CHECKER_VERSION
            or self.samples != config.samples
            or {dc.dc_id for dc in self.dcs} != set(config.dc_ids)
        ):
            return False
        return self.validation_key == config.validation_key or (
            self.checker_version == MIN_VALIDATED_CHECKER_VERSION
            and self.validation_key is None
        )

    def matches_health(self, config):
        if self.check_kind == "full":
            return self.matches_policy(config)
        return (
            self.checker_version >= CHECKER_VERSION
            and not self.checker_error
            and self.samples == 1
            and {dc.dc_id for dc in self.dcs} == set(config.dc_ids)
            and self.validation_key == config.validation_key
            and self.health_validation_key == config.health_validation_key
        )

    @property
    def ip(self):
        value = next((dc.ip for dc in self.dcs if dc.ip and dc.rtt_ms), None)
        value = value or next((dc.ip for dc in self.dcs if dc.ip), None)
        return str(ipaddress.ip_address(value)) if value else None


def rating(observations: list[ProxyObservation]) -> dict:
    """One complete logical round is one trial, as in the VPN reliability score."""
    rounds = {}
    for item in sorted(observations, key=lambda item: (item.checked_at, str(item.id))):
        if item.quality_round:
            rounds.setdefault(item.round_id or item.id, item)
    recent = list(rounds.values())[-HISTORY_WINDOW:]
    total = len(recent)
    successes = sum(item.working for item in recent)
    if not total:
        return dict(stability_score=0.0, speed_score=0.0, rating=0.0, latency_ms=None)
    p, z = successes / total, 1.96
    stability = (
        100
        * (
            p
            + z * z / (2 * total)
            - z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
        )
        / (1 + z * z / total)
    )
    timings = [
        0.5 * dc.first_response_ms + 0.5 * median(dc.rtt_ms)
        for item in recent
        if item.working
        for dc in item.dcs
    ]
    latency = median(timings) if timings else None
    speed = 100 / (1 + latency / 250) if latency is not None else 0.0
    return dict(
        stability_score=round(max(0.0, stability), 4),
        speed_score=round(speed, 4),
        rating=round(stability * (0.5 + 0.5 * speed / 100), 4)
        if recent[-1].working
        else 0.0,
        latency_ms=latency,
    )


def country_flag(code: str | None) -> str:
    if not code or not re.fullmatch("[A-Z]{2}", code):
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)
