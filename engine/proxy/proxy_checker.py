"""Health-checks proxies: reachability + latency, via a concurrent thread pool
(kept sync + requests since checks are short-lived, unlike the browser workers)."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

from models import ProxyRecord


def check_proxy(proxy: ProxyRecord, check_url: str, timeout_s: int) -> ProxyRecord:
    proxies = {"http": proxy.url, "https": proxy.url}
    start = time.perf_counter()
    try:
        resp = requests.get(check_url, proxies=proxies, timeout=timeout_s)
        proxy.alive = resp.ok
        proxy.latency_ms = (time.perf_counter() - start) * 1000
    except requests.RequestException:
        proxy.alive = False
        proxy.latency_ms = None
    proxy.last_checked = datetime.now()
    return proxy


def check_all(
    proxies: list[ProxyRecord], check_url: str, timeout_s: int, max_workers: int = 20
) -> list[ProxyRecord]:
    results: list[ProxyRecord] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(check_proxy, p, check_url, timeout_s) for p in proxies]
        for future in as_completed(futures):
            results.append(future.result())
    return results
