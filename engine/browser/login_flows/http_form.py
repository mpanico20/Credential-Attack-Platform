"""Generic HTML form login flow, driven entirely by the selectors configured
per-target in config.yaml - no per-target subclassing needed.

After submit we poll the page (up to timeout_s) for the first indicator that
appears, in priority order:

    SUCCESS  ->  LOCKED  ->  BLOCKED/CAPTCHA  ->  FAILURE  ->  (timeout) ERROR

Polling (instead of a fixed sleep) avoids false ERRORs when the response is
slow under load or through a proxy, and lets a defense page (lockout, WAF,
CAPTCHA) be classified distinctly from an infrastructure error.
"""
from __future__ import annotations

import random
import time

from browser.cdp_session import CDPSession
from captcha.handler import handle_captcha
from models import Credential, Outcome, Target

_DEFAULT_CAPTCHA_SELECTORS = [
    "iframe[src*='recaptcha']",
    "iframe[src*='hcaptcha']",
    "iframe[src*='turnstile']",
    ".g-recaptcha",
    ".h-captcha",
    ".cf-turnstile",
]

_POLL_INTERVAL_S = 0.3


def _human_pause(low: float = 0.4, high: float = 1.1) -> None:
    """Gap a real user would leave between reading a field and acting on it.
    press_keys() already paces individual keystrokes - this covers the time
    between actions (page load -> first field, field -> field, before submit)."""
    time.sleep(random.uniform(low, high))


def _captcha_present(session: CDPSession, target: Target) -> bool:
    selectors = _DEFAULT_CAPTCHA_SELECTORS.copy()
    if target.captcha_indicator:
        selectors.insert(0, target.captcha_indicator)
    for sel in selectors:
        try:
            if session.is_visible(sel):
                return True
        except Exception:
            continue
    return False


def _classify_once(session: CDPSession, target: Target) -> tuple[Outcome | None, dict]:
    """One pass over the indicators in priority order. Returns (outcome, metadata),
    or (None, {}) when nothing has appeared on the page yet."""
    if target.success_indicator and session.is_visible(target.success_indicator):
        return Outcome.SUCCESS, {}
    if target.lockout_indicator and session.is_visible(target.lockout_indicator):
        return Outcome.LOCKED, {"block_reason": "lockout"}
    if _captcha_present(session, target):
        return Outcome.BLOCKED, {"block_reason": "captcha", "captcha_encountered": True}
    if target.block_indicator and session.is_visible(target.block_indicator):
        return Outcome.BLOCKED, {"block_reason": "block"}
    if target.failure_indicator and session.is_visible(target.failure_indicator):
        return Outcome.FAILURE, {}
    return None, {}


def _wait_for_outcome(
    session: CDPSession, target: Target, timeout_s: int
) -> tuple[Outcome, str | None, dict]:
    deadline = time.perf_counter() + timeout_s
    while True:
        outcome, meta = _classify_once(session, target)
        if outcome is not None:
            return outcome, None, meta
        if time.perf_counter() >= deadline:
            return Outcome.ERROR, "No indicator matched within timeout", {}
        time.sleep(_POLL_INTERVAL_S)


def attempt_login(
    session: CDPSession, target: Target, credential: Credential, timeout_s: int,
    captcha_cfg=None, captcha_solver=None,
) -> tuple[Outcome, float, str | None, dict]:
    """Returns (outcome, latency_ms, error, metadata).

    If a CAPTCHA module is wired (captcha_cfg + captcha_solver), after filling
    the form we detect a CAPTCHA and: with a solver -> solve + inject the token
    and proceed; without a solver -> the attempt is BLOCKED by the CAPTCHA. A
    risk-based CAPTCHA that only appears AFTER submit is still caught by
    _wait_for_outcome (via _captcha_present) and classified BLOCKED.
    """
    start = time.perf_counter()
    cap_meta: dict = {}
    try:
        session.goto(target.base_url)
        _human_pause()

        session.type_into(target.username_selector, credential.username)
        _human_pause()
        session.type_into(target.password_selector, credential.password)
        _human_pause(0.2, 0.6)

        if captcha_cfg is not None and captcha_solver is not None:
            cap = handle_captcha(
                session, captcha_cfg, captcha_solver,
                page_url=target.base_url, sitekey_override=target.captcha_sitekey,
            )
            if cap["present"]:
                cap_meta = {
                    "captcha_type": cap["type"],
                    "captcha_solver": getattr(captcha_solver, "name", None),
                    "captcha_outcome": cap["outcome"],
                    "token_obtained": cap["outcome"] in ("solved", "auto_passed"),
                    "solve_time_ms": cap["solve_time_ms"],
                }
                if cap["outcome"] == "blocked":
                    latency_ms = (time.perf_counter() - start) * 1000
                    return (Outcome.BLOCKED, latency_ms, None,
                            {"block_reason": "captcha", "captcha_encountered": True, **cap_meta})
                if cap["outcome"] == "error":
                    latency_ms = (time.perf_counter() - start) * 1000
                    return Outcome.ERROR, latency_ms, cap["error"], dict(cap_meta)

        session.click(target.submit_selector)

        outcome, error, meta = _wait_for_outcome(session, target, timeout_s)
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        return Outcome.ERROR, latency_ms, str(exc), dict(cap_meta)

    latency_ms = (time.perf_counter() - start) * 1000
    if cap_meta:
        meta = {**meta, **cap_meta}
    return outcome, latency_ms, error, meta
