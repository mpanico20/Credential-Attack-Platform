"""Shared data structures used across the platform."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class LoginType(str, Enum):
    HTTP_FORM = "http_form"
    LDAP = "ldap"
    SSH = "ssh"


class AttackType(str, Enum):
    CREDENTIAL_STUFFING = "credential_stuffing"
    PASSWORD_SPRAY = "password_spray"
    BRUTE_FORCE = "brute_force"


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    LOCKED = "locked"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass(frozen=True)
class Credential:
    username: str
    password: str
    source: str = "combo"


@dataclass(frozen=True)
class Target:
    name: str
    base_url: str
    login_type: LoginType
    username_selector: str | None = None
    password_selector: str | None = None
    submit_selector: str | None = None
    success_indicator: str | None = None
    failure_indicator: str | None = None
    lockout_indicator: str | None = None
    block_indicator: str | None = None
    captcha_indicator: str | None = None
    captcha_when: str = "after_submit"
    captcha_sitekey: str | None = None
    ldap_server: str | None = None
    ldap_base_dn: str | None = None
    ldap_user_dn_template: str | None = None
    ssh_host: str | None = None
    ssh_port: int = 22


@dataclass
class ProxyRecord:
    address: str
    scheme: str = "http"
    username: str | None = None
    password: str | None = None
    country: str | None = None
    alive: bool | None = None
    latency_ms: float | None = None
    last_checked: datetime | None = None

    @property
    def url(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username else ""
        return f"{self.scheme}://{auth}{self.address}"

    @property
    def cdp_proxy_string(self) -> str:
        """Format expected by seleniumbase's CDP `proxy=` kwarg."""
        if self.username:
            return f"{self.username}:{self.password}@{self.address}"
        return self.address


@dataclass
class AttemptResult:
    timestamp: datetime
    target_name: str
    attack_type: AttackType
    username: str
    password: str
    outcome: Outcome
    latency_ms: float
    delay_applied_ms: float | None = None
    proxy: str | None = None
    mutation_applied: str | None = None
    technique_id: str | None = None
    error: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp.isoformat(),
            "target_name": self.target_name,
            "attack_type": self.attack_type.value,
            "username": self.username,
            "password": self.password,
            "outcome": self.outcome.value,
            "latency_ms": self.latency_ms,
            "delay_applied_ms": self.delay_applied_ms,
            "proxy": self.proxy,
            "mutation_applied": self.mutation_applied,
            "technique_id": self.technique_id,
            "error": self.error,
        }
        d.update(self.metadata)
        return d
