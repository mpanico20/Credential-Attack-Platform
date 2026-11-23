"""HaveIBeenPwned v3 API client - proactive check for whether a domain's
accounts show up in known breaches. Requires a paid API key (hibp-api-key
header); the API enforces a rate limit, so calls are spaced out."""
from __future__ import annotations

import time

import requests

_BASE_URL = "https://haveibeenpwned.com/api/v3"
_MIN_INTERVAL_S = 1.5


class HIBPClient:
    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError("HIBP API key is required")
        self.api_key = api_key
        self._last_call = 0.0

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_call
        if elapsed < _MIN_INTERVAL_S:
            time.sleep(_MIN_INTERVAL_S - elapsed)
        self._last_call = time.monotonic()

    def breaches_for_account(self, email: str) -> list[dict]:
        self._throttle()
        resp = requests.get(
            f"{_BASE_URL}/breachedaccount/{email}",
            headers={"hibp-api-key": self.api_key, "user-agent": "credential-attack-platform"},
            params={"truncateResponse": "false"},
            timeout=15,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json()

    def check_domain(self, emails: list[str]) -> dict[str, list[dict]]:
        return {email: self.breaches_for_account(email) for email in emails}
