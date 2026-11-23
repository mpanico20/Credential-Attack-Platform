"""Rotation policy over the pool of alive proxies. Thread-safe: attack_engine
pulls one proxy per worker task from possibly-concurrent threads."""
from __future__ import annotations

import itertools
import random
import threading

from models import ProxyRecord


class ProxyManager:
    def __init__(self, proxies: list[ProxyRecord], rotation: str = "round_robin"):
        self._alive = [p for p in proxies if p.alive]
        if not self._alive:
            raise ValueError("No alive proxies available - run proxy-check first")
        self.rotation = rotation
        self._lock = threading.Lock()
        self._cycle = itertools.cycle(self._alive)

    def get_proxy(self) -> ProxyRecord:
        with self._lock:
            if self.rotation == "random":
                return random.choice(self._alive)
            return next(self._cycle)

    def mark_dead(self, proxy: ProxyRecord) -> None:
        with self._lock:
            if proxy in self._alive:
                self._alive.remove(proxy)
                self._cycle = itertools.cycle(self._alive)
