"""Strict leased-job envelope. Incoming API data cannot add arbitrary commands."""

from datetime import datetime
import ipaddress
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class Policy(BaseModel):
    model_config = {"extra": "forbid", "hide_input_in_errors": True}
    settings: dict
    validation_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    health_validation_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    checker_version: Literal[4]


class Lease(BaseModel):
    model_config = {"extra": "forbid", "hide_input_in_errors": True}
    id: UUID
    kind: Literal["vpn", "mtproxy"]
    check_kind: Literal["full", "health"]
    node_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    preferred_ip: str
    network_epoch: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    previously_verified: bool
    target: dict
    policy: Policy

    @model_validator(mode="after")
    def safe_job(self):
        if not ipaddress.ip_address(self.preferred_ip).is_global:
            raise ValueError("A scanner job must target a public IP")
        if (
            self.issued_at.tzinfo is None
            or self.expires_at.tzinfo is None
            or not 0 < (self.expires_at - self.issued_at).total_seconds() <= 3600
        ):
            raise ValueError("Invalid job time range")
        return self
