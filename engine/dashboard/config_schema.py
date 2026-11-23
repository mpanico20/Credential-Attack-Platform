"""Config helpers for the editor page: the default config, file CRUD on
`configs/`, and validation of the raw YAML the editor produces.

Validation is intentionally delegated to the engine itself (`config.load_config`)
so there is no schema to keep in sync by hand; `validate()` only adds the few
domain checks the loader does not enforce.
"""
from __future__ import annotations

import glob
from copy import deepcopy
from pathlib import Path

import yaml

from dashboard.webapp_common import CONFIGS_DIR

BACKEND_OPTIONS = ["cdp", "camoufox"]
LOGIN_TYPE_OPTIONS = ["http_form", "ldap", "ssh"]

DEFAULT_TARGET = {
    "name": "portal-ip",
    "base_url": "https://portal.local/login.php",
    "login_type": "http_form",
    "username_selector": "#username",
    "password_selector": "#password",
    "submit_selector": "button[type='submit']",
    "success_indicator": "a[href='logout.php']",
    "failure_indicator": ".alert-error",
    "lockout_indicator": ".alert-warning",
    "block_indicator": ".alert-rate",
    "captcha_indicator": None,
    "captcha_when": "after_submit",
    "captcha_sitekey": None,
    "ldap_server": None,
    "ldap_base_dn": None,
    "ldap_user_dn_template": None,
    "ssh_host": None,
    "ssh_port": 22,
}

DEFAULT_CONFIG = {
    "concurrency": {"max_workers": 5},
    "rate_limit": {"min_delay_s": 0.0, "max_delay_s": 0.0, "jitter_s": 0.0},
    "browser": {
        "headless": True,
        "timeout_s": 30,
        "backend": "cdp",
        "binary_location": None,
        "headed_on_linux": False,
    },
    "camoufox": {"os": "windows", "locale": "it-IT", "geoip": True, "humanize": True},
    "identity": {
        "requests_per_identity": 1000,
        "requests_per_identity_min": None,
        "requests_per_identity_max": None,
    },
    "backoff": {
        "enabled": False,
        "lockout_cooldown_s": 900,
        "block_base_delay_s": 5,
        "block_max_delay_s": 120,
        "backoff_factor": 2.0,
    },
    "proxy": {
        "source_file": "proxies/proxies.txt",
        "check_url": "https://httpbin.org/ip",
        "check_timeout_s": 10,
        "rotation": "round_robin",
    },
    "logging": {"output_dir": "logs"},
    "wazuh": {
        "host": "", "port": 9200, "username": "", "password": "",
        "verify_ssl": False, "alerts_index": "wazuh-alerts-*",
    },
    "hibp": {"api_key": ""},
    "captcha": {
        "type": "auto",
        "solver": "none",
        "api_key": "",
        "invisible": False,
        "action": None,
        "min_score": None,
        "poll_timeout_s": 120,
        "auto_wait_s": 6,
    },
    "exploit": {
        "enabled": False,
        "base_url": "",
        "login_path": "login.php",
        "upload_path": "upload.php",
        "upload_field": "file",
        "uploads_dir": "uploads",
        "lhost": "127.0.0.1",
        "bind_host": "",
        "lport": 4444,
        "payload": "php_reverse_fsock",
        "payload_template_file": None,
        "verify_cmd": "id; hostname; uname -a",
        "callback_timeout_s": 15,
        "trigger_read_timeout_s": 4,
        "http_timeout_s": 15,
        "verify_ssl": False,
        "run_once": True,
    },
    "targets": [deepcopy(DEFAULT_TARGET)],
}


def list_configs() -> list[str]:
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    files = glob.glob(str(CONFIGS_DIR / "*.yaml")) + glob.glob(str(CONFIGS_DIR / "*.yml"))
    return sorted(Path(f).name for f in files)


def load_config_file(name: str) -> dict:
    """Parsed YAML as a dict (used to read target names in the launcher)."""
    path = CONFIGS_DIR / name
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or deepcopy(DEFAULT_CONFIG)


def delete_config_file(name: str) -> bool:
    """Delete a config from configs/; returns True if a file was removed.
    Rejects anything but a bare file name inside CONFIGS_DIR (no path traversal)."""
    path = CONFIGS_DIR / Path(name).name
    if path.exists() and path.parent == CONFIGS_DIR:
        path.unlink()
        return True
    return False


def default_config_text() -> str:
    """The default config as YAML text, for a fresh editor buffer."""
    return yaml.dump(DEFAULT_CONFIG, sort_keys=False, default_flow_style=False,
                     allow_unicode=True)


def load_config_text(name: str) -> str:
    """Raw file text, so the editor preserves comments and formatting."""
    return (CONFIGS_DIR / name).read_text(encoding="utf-8")


def save_config_text(name: str, text: str) -> Path:
    """Save the editor buffer verbatim (keeps the user's comments/formatting)."""
    if not (name.endswith(".yaml") or name.endswith(".yml")):
        name += ".yaml"
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    path = CONFIGS_DIR / name
    path.write_text(text, encoding="utf-8")
    return path


def validate_yaml_text(text: str) -> tuple[bool, dict | None, list[str]]:
    """Validate editor text the way the engine would load it, in three layers:
    the YAML parses, it loads through the engine's own load_config (so unknown
    keys and wrong types surface exactly as at runtime), and the domain checks in
    validate(). Returns (ok, parsed_data, messages)."""
    import os
    import tempfile

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return False, None, [f"YAML non valido: {exc}"]
    if not isinstance(data, dict):
        return False, None, ["Il contenuto non e' una mappa YAML."]

    messages: list[str] = []
    from config import load_config

    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(text)
            tmp = f.name
        load_config(tmp)
    except Exception as exc:
        messages.append(f"load_config: {exc}")
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    messages.extend(validate(data))
    return (len(messages) == 0), data, messages


def target_names(data: dict) -> list[str]:
    return [t.get("name", "") for t in data.get("targets", []) if t.get("name")]


def validate(data: dict) -> list[str]:
    """Domain checks on top of load_config. Returns human-readable problems
    (empty list = OK)."""
    problems: list[str] = []
    backend = data.get("browser", {}).get("backend")
    if backend not in BACKEND_OPTIONS:
        problems.append(f"browser.backend '{backend}' non valido (atteso: {BACKEND_OPTIONS}).")

    targets = data.get("targets", [])
    if not targets:
        problems.append("Nessun target definito.")
    names = [t.get("name") for t in targets]
    if len(names) != len(set(names)):
        problems.append("Nomi di target duplicati: devono essere univoci.")

    for t in targets:
        lt = t.get("login_type")
        if lt not in LOGIN_TYPE_OPTIONS:
            problems.append(f"target '{t.get('name')}': login_type '{lt}' non valido.")
        if lt == "http_form" and not t.get("base_url"):
            problems.append(f"target '{t.get('name')}': manca base_url.")
        if lt == "ldap" and not t.get("ldap_server"):
            problems.append(f"target '{t.get('name')}': login_type ldap ma manca ldap_server.")
        if lt == "ssh" and not t.get("ssh_host"):
            problems.append(f"target '{t.get('name')}': login_type ssh ma manca ssh_host.")
    return problems
