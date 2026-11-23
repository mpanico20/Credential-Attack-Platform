"""Loads config.yaml into typed dataclasses."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from models import LoginType, Target


@dataclass
class ConcurrencyConfig:
    max_workers: int = 8


@dataclass
class RateLimitConfig:
    min_delay_s: float = 1.0
    max_delay_s: float = 3.0
    jitter_s: float = 1.5


@dataclass
class BrowserConfig:
    headless: bool = True
    timeout_s: int = 30
    backend: str = "cdp"
    binary_location: str | None = None
    headed_on_linux: bool = False


@dataclass
class CamoufoxConfig:
    os: str = "windows"
    locale: str | None = None
    geoip: bool = True
    humanize: bool = True


@dataclass
class IdentityConfig:
    requests_per_identity: int = 5
    requests_per_identity_min: int | None = None
    requests_per_identity_max: int | None = None

    def next_budget(self) -> int:
        """A fresh per-identity attempt budget: random in [min, max] when both are
        set, else the fixed `requests_per_identity`."""
        lo, hi = self.requests_per_identity_min, self.requests_per_identity_max
        if lo is not None and hi is not None:
            lo = max(1, int(lo))
            hi = max(lo, int(hi))
            return random.randint(lo, hi)
        return max(1, int(self.requests_per_identity))


@dataclass
class BackoffConfig:
    enabled: bool = True
    lockout_cooldown_s: float = 900.0
    block_base_delay_s: float = 5.0
    block_max_delay_s: float = 120.0
    backoff_factor: float = 2.0


@dataclass
class ProxyConfig:
    source_file: str = "proxies/proxies.txt"
    check_url: str = "https://httpbin.org/ip"
    check_timeout_s: int = 10
    rotation: str = "round_robin"


@dataclass
class LoggingConfig:
    output_dir: str = "logs"


@dataclass
class WazuhConfig:
    host: str = ""
    port: int = 9200
    username: str = ""
    password: str = ""
    verify_ssl: bool = False
    alerts_index: str = "wazuh-alerts-*"


@dataclass
class HIBPConfig:
    api_key: str = ""


@dataclass
class CaptchaConfig:
    type: str = "auto"
    solver: str = "none"
    api_key: str = ""
    invisible: bool = False
    action: str | None = None
    min_score: float | None = None
    poll_timeout_s: float = 120.0
    auto_wait_s: float = 6.0


@dataclass
class ExploitConfig:
    enabled: bool = False
    base_url: str = ""
    login_path: str = "login.php"
    upload_path: str = "upload.php"
    upload_field: str = "file"
    uploads_dir: str = "uploads"
    lhost: str = "127.0.0.1"
    bind_host: str = ""
    lport: int = 4444
    payload: str = "php_reverse_fsock"
    payload_template_file: str | None = None
    verify_cmd: str = "id; hostname; uname -a"
    callback_timeout_s: float = 15.0
    trigger_read_timeout_s: float = 4.0
    http_timeout_s: float = 15.0
    verify_ssl: bool = False
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    run_once: bool = True


@dataclass
class Config:
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    camoufox: CamoufoxConfig = field(default_factory=CamoufoxConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    backoff: BackoffConfig = field(default_factory=BackoffConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    wazuh: WazuhConfig = field(default_factory=WazuhConfig)
    hibp: HIBPConfig = field(default_factory=HIBPConfig)
    captcha: CaptchaConfig = field(default_factory=CaptchaConfig)
    exploit: ExploitConfig = field(default_factory=ExploitConfig)
    targets: list[Target] = field(default_factory=list)

    def get_target(self, name: str) -> Target:
        for t in self.targets:
            if t.name == name:
                return t
        raise KeyError(f"Unknown target: {name}")


def _target_from_dict(d: dict) -> Target:
    return Target(
        name=d["name"],
        base_url=d.get("base_url", ""),
        login_type=LoginType(d["login_type"]),
        username_selector=d.get("username_selector"),
        password_selector=d.get("password_selector"),
        submit_selector=d.get("submit_selector"),
        success_indicator=d.get("success_indicator"),
        failure_indicator=d.get("failure_indicator"),
        lockout_indicator=d.get("lockout_indicator"),
        block_indicator=d.get("block_indicator"),
        captcha_indicator=d.get("captcha_indicator"),
        captcha_when=d.get("captcha_when", "after_submit"),
        captcha_sitekey=d.get("captcha_sitekey"),
        ldap_server=d.get("ldap_server"),
        ldap_base_dn=d.get("ldap_base_dn"),
        ldap_user_dn_template=d.get("ldap_user_dn_template"),
        ssh_host=d.get("ssh_host"),
        ssh_port=d.get("ssh_port", 22),
    )


def load_config(path: str | Path = "config.yaml") -> Config:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    return Config(
        concurrency=ConcurrencyConfig(**raw.get("concurrency", {})),
        rate_limit=RateLimitConfig(**raw.get("rate_limit", {})),
        browser=BrowserConfig(**raw.get("browser", {})),
        camoufox=CamoufoxConfig(**raw.get("camoufox", {})),
        identity=IdentityConfig(**raw.get("identity", {})),
        backoff=BackoffConfig(**raw.get("backoff", {})),
        proxy=ProxyConfig(**raw.get("proxy", {})),
        logging=LoggingConfig(**raw.get("logging", {})),
        wazuh=WazuhConfig(**raw.get("wazuh", {})),
        hibp=HIBPConfig(**raw.get("hibp", {})),
        captcha=CaptchaConfig(**raw.get("captcha", {})),
        exploit=ExploitConfig(**raw.get("exploit", {})),
        targets=[_target_from_dict(t) for t in raw.get("targets", [])],
    )
