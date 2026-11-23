"""Adaptive backoff: a feedback loop that reacts to defensive outcomes and
steers the pacing of subsequent attempts. Shared across all worker threads, so
it is thread-safe.

Reactions (as agreed with the advisor):
  * LOCKED  -> the account enters a cooldown for `lockout_cooldown_s`. Further
    attempts on that account during the window are SKIPPED, not retried
    (lockout-aware: a real attacker stops hammering a locked account instead of
    burning attempts and keeping it locked).
  * BLOCKED (incl. CAPTCHA, block_reason="captcha") -> a global block delay grows
    exponentially and is applied before every subsequent attempt, until a
    non-block outcome decays it. The next attempt already runs in a fresh session
    (new fingerprint + rotated proxy), which is the "change identity" part; on
    CAPTCHA that identity change is the meaningful reaction.
  * SUCCESS / FAILURE -> decays the block level back down (defense eased off).
  * ERROR -> neutral. Infra noise (or a dropped SSH connection) is not treated as
    a defense here; repeated ERRORs are left for offline analysis to interpret.

Block delay formula (when consecutive_blocks = n > 0), "full jitter":
    ceiling = min(base * factor^(n-1), cap)
    delay   = random(0, ceiling)
Jitter matters: a fixed/deterministic backoff is itself a detectable pattern, so
the exponential value is used as a ceiling and the actual sleep is randomized.
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass

from config import BackoffConfig
from models import Outcome


@dataclass(frozen=True)
class BackoffDecision:
    skip: bool
    delay_applied_s: float
    reason: str | None = None
    cooldown_remaining_s: float | None = None


class BackoffController:
    def __init__(self, cfg: BackoffConfig):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._account_until: dict[str, float] = {}
        self._consecutive_blocks = 0

    def _current_block_delay(self) -> float:
        """Global block delay from the consecutive-block count (call under lock).
        Exponential ceiling + full jitter, so the delay is not a fixed pattern."""
        n = self._consecutive_blocks
        if n <= 0:
            return 0.0
        ceiling = self.cfg.block_base_delay_s * (self.cfg.backoff_factor ** (n - 1))
        ceiling = min(ceiling, self.cfg.block_max_delay_s)
        return random.uniform(0.0, ceiling)

    def before_attempt(self, account_key: str) -> BackoffDecision:
        """Called by a worker before an attempt. May sleep for the current block
        delay. Returns a decision; if skip=True the caller must NOT contact the
        target (the account is still in its lockout cooldown)."""
        if not self.cfg.enabled:
            return BackoffDecision(skip=False, delay_applied_s=0.0)

        now = time.monotonic()
        with self._lock:
            deadline = self._account_until.get(account_key, 0.0)
            if deadline > now:
                return BackoffDecision(
                    skip=True,
                    delay_applied_s=0.0,
                    reason="account_cooldown",
                    cooldown_remaining_s=deadline - now,
                )
            block_delay = self._current_block_delay()

        if block_delay > 0:
            time.sleep(block_delay)
        return BackoffDecision(skip=False, delay_applied_s=block_delay)

    def record(self, outcome: Outcome, meta: dict, account_key: str) -> None:
        """Called by a worker after an attempt, to update the shared state."""
        if not self.cfg.enabled:
            return
        with self._lock:
            if outcome == Outcome.LOCKED:
                self._account_until[account_key] = time.monotonic() + self.cfg.lockout_cooldown_s
            elif outcome == Outcome.BLOCKED:
                self._consecutive_blocks += 1
            elif outcome in (Outcome.SUCCESS, Outcome.FAILURE):
                self._consecutive_blocks = max(0, self._consecutive_blocks - 1)

    def block_level(self) -> int:
        with self._lock:
            return self._consecutive_blocks

    def accounts_in_cooldown(self) -> int:
        now = time.monotonic()
        with self._lock:
            return sum(1 for d in self._account_until.values() if d > now)
