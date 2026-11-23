"""Thin wrapper around seleniumbase's Pure CDP mode (sb_cdp.Chrome).

Each Chrome() instance opens its own asyncio event loop internally
(seleniumbase.core.sb_cdp.Chrome.__init__ calls asyncio.new_event_loop()),
so it's safe - and required for real concurrency - to run one instance
per worker thread rather than trying to share one asyncio loop across
sessions. See AttackEngine, whose worker threads each own one session for
this reason.
"""
from __future__ import annotations

import platform as _sys_platform
from contextlib import AbstractContextManager

from seleniumbase import sb_cdp

from config import BrowserConfig
from evasion.fingerprint import Fingerprint, build_fingerprint
from evasion.webrtc import webrtc_leak_prevention_args
from evasion import webgl_spoof
from evasion import client_hints
from models import ProxyRecord


class CDPSession(AbstractContextManager):
    def __init__(
        self,
        browser_cfg: BrowserConfig,
        proxy: ProxyRecord | None = None,
        fingerprint: Fingerprint | None = None,
        spoof_gpu: bool = False,
    ):
        self.browser_cfg = browser_cfg
        self.proxy = proxy
        self.fingerprint = fingerprint or build_fingerprint(
            proxy.country if proxy else None
        )
        self.spoof_gpu = spoof_gpu
        self.driver = None

    def __enter__(self) -> "CDPSession":
        kwargs: dict = {"headless": self.browser_cfg.headless}
        kwargs.update(self.fingerprint.as_cdp_kwargs())
        if self.browser_cfg.binary_location:
            kwargs["binary_location"] = self.browser_cfg.binary_location
        if (
            _sys_platform.system() == "Linux"
            and not self.browser_cfg.headless
            and self.browser_cfg.headed_on_linux
        ):
            kwargs["headed"] = True
        if self.proxy:
            kwargs["proxy"] = self.proxy.cdp_proxy_string
        browser_args = webrtc_leak_prevention_args()
        if _sys_platform.system() == "Linux":
            browser_args += ["--no-sandbox", "--disable-dev-shm-usage"]
        kwargs["browser_args"] = browser_args
        self.driver = sb_cdp.Chrome(**kwargs)
        client_hints.inject(
            self.driver, self.fingerprint.user_agent, self.fingerprint.platform
        )
        if self.spoof_gpu:
            webgl_spoof.inject(
                self.driver, self.fingerprint.gpu_vendor, self.fingerprint.gpu_renderer
            )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.driver:
            self.driver.quit()
        return False

    def goto(self, url: str) -> None:
        self.driver.open(url)

    def type_into(self, selector: str, text: str) -> None:
        self.driver.press_keys(selector, text)

    def click(self, selector: str) -> None:
        self.driver.click(selector)

    def submit(self, selector: str) -> None:
        self.driver.submit(selector)

    def is_visible(self, selector: str) -> bool:
        return self.driver.is_element_visible(selector)

    def page_source(self) -> str:
        return self.driver.get_page_source()

    def evaluate(self, script: str):
        """Run JS in the page and return its value. Used by the CAPTCHA module
        to read the sitekey and inject the solved token."""
        return self.driver.evaluate(script)

    def sleep(self, seconds: float) -> None:
        self.driver.sleep(seconds)

    def reset_session_state(self) -> bool:
        """Clear all persistent auth state - cookies (incl. HttpOnly) AND
        localStorage/sessionStorage - so the login form reappears after a
        successful login, WITHOUT rotating the identity (same IP + fingerprint).
        Covers both cookie-based apps and SPAs that keep a token in web storage.
        Returns False if anything could not be cleared, so the caller can fall
        back to rotating the session for a guaranteed-clean state."""
        ok = True
        try:
            self.driver.clear_cookies()
        except Exception:
            ok = False
        try:
            self.driver.evaluate(
                "(function(){try{localStorage.clear();sessionStorage.clear();}catch(e){}})()"
            )
        except Exception:
            ok = False
        return ok
