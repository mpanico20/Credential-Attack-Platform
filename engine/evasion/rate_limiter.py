"""Low-and-slow pacing: delay + jitter applied between attempts, per worker."""
from __future__ import annotations

import random
import time

from config import RateLimitConfig


class RateLimiter:
    def __init__(self, cfg: RateLimitConfig):
        self.cfg = cfg

    def wait(self) -> float:
        """Blocking sleep (called from a worker thread). Returns the delay applied."""
        base = random.uniform(self.cfg.min_delay_s, self.cfg.max_delay_s)
        jitter = random.uniform(0, self.cfg.jitter_s)
        delay = base + jitter
        time.sleep(delay)
        return delay
