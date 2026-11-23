"""Camoufox backend for browser-driven login flows.

Exposes the SAME interface as browser.cdp_session.CDPSession (goto / type_into /
click / submit / is_visible / page_source / sleep + context manager), so the HTTP
form flow (browser.login_flows.http_form) can drive either backend unchanged.
The engine picks the backend from config (browser.backend = "cdp" | "camoufox").

Why a second backend: Camoufox spoofs the fingerprint at the C++ level (worker-
consistent, no CDP traces), so it can present a DIFFERENT OS than the host while
staying coherent - something the CDP backend can't do (see evasion.fingerprint).
Running the two side by side is what lets the thesis compare them empirically.

Camoufox is imported lazily inside __enter__ so importing this module (and the
whole engine) never requires Camoufox to be installed - only actually selecting
the camoufox backend does.
"""
from __future__ import annotations

import random
import time
from contextlib import AbstractContextManager

from config import BrowserConfig, CamoufoxConfig
from models import ProxyRecord

_OS_CHOICES = ("windows", "macos", "linux")


def _proxy_to_playwright(proxy: ProxyRecord) -> dict:
    """ProxyRecord -> Playwright/Camoufox proxy dict."""
    server = f"{proxy.scheme}://{proxy.address}"
    d: dict = {"server": server}
    if proxy.username:
        d["username"] = proxy.username
        d["password"] = proxy.password or ""
    return d


class CamoufoxSession(AbstractContextManager):
    def __init__(
        self,
        browser_cfg: BrowserConfig,
        camoufox_cfg: CamoufoxConfig,
        proxy: ProxyRecord | None = None,
    ):
        self.browser_cfg = browser_cfg
        self.camoufox_cfg = camoufox_cfg
        self.proxy = proxy
        self._cf = None
        self._browser = None
        self._context = None
        self._page = None

    def __enter__(self) -> "CamoufoxSession":
        from camoufox.sync_api import Camoufox

        os_choice = self.camoufox_cfg.os
        if os_choice == "random":
            os_choice = random.choice(_OS_CHOICES)

        kwargs: dict = {
            "headless": self.browser_cfg.headless,
            "os": os_choice,
            "locale": self.camoufox_cfg.locale,
            "geoip": self.camoufox_cfg.geoip,
            "humanize": self.camoufox_cfg.humanize,
        }
        if self.proxy:
            kwargs["proxy"] = _proxy_to_playwright(self.proxy)

        self._cf = Camoufox(**kwargs)
        self._browser = self._cf.__enter__()
        self._context = self._browser.new_context(ignore_https_errors=True)
        self._context.set_default_timeout(self.browser_cfg.timeout_s * 1000)
        self._page = self._context.new_page()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            if self._context:
                self._context.close()
        finally:
            if self._cf:
                self._cf.__exit__(exc_type, exc_val, exc_tb)
        return False

    def goto(self, url: str) -> None:
        self._page.goto(
            url, wait_until="domcontentloaded", timeout=self.browser_cfg.timeout_s * 1000
        )

    def type_into(self, selector: str, text: str) -> None:
        loc = self._page.locator(selector).first
        loc.press_sequentially(text, delay=random.uniform(40, 55))

    def click(self, selector: str) -> None:
        self._page.locator(selector).first.click(timeout=self.browser_cfg.timeout_s * 1000)

    def submit(self, selector: str) -> None:
        self._page.locator(selector).first.click(timeout=self.browser_cfg.timeout_s * 1000)

    def is_visible(self, selector: str) -> bool:
        try:
            return self._page.locator(selector).first.is_visible()
        except Exception:
            return False

    def page_source(self) -> str:
        return self._page.content()

    def evaluate(self, script: str):
        """Run JS in the page and return its value. Used by the CAPTCHA module
        to read the sitekey and inject the solved token. Mirrors CDPSession."""
        return self._page.evaluate(script)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def reset_session_state(self) -> bool:
        """Clear all persistent auth state - cookies (incl. HttpOnly) AND
        localStorage/sessionStorage - so the login form reappears after a
        successful login, WITHOUT rotating the identity (same IP + fingerprint).
        Covers both cookie-based apps and SPAs that keep a token in web storage.
        Returns False if anything could not be cleared, so the caller can fall
        back to rotating the session for a guaranteed-clean state."""
        ok = True
        try:
            self._context.clear_cookies()
        except Exception:
            ok = False
        try:
            self._page.evaluate(
                "(function(){try{localStorage.clear();sessionStorage.clear();}catch(e){}})()"
            )
        except Exception:
            ok = False
        return ok
