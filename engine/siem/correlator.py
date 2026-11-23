"""Joins the platform's own attempt log with Wazuh alerts to compute the
comparative metrics the dashboard shows (Success Rate, Time-To-Detection,
block rate) - with and without defenses active."""
from __future__ import annotations

from datetime import datetime
from statistics import mean, median

from models import Outcome

_ALERT_TIME_FMT_CANDIDATES = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")


def _parse_alert_timestamp(raw: str) -> datetime:
    for fmt in _ALERT_TIME_FMT_CANDIDATES:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return datetime.fromisoformat(raw)


def success_rate(attempts: list[dict]) -> float:
    if not attempts:
        return 0.0
    successes = sum(1 for a in attempts if a["outcome"] == Outcome.SUCCESS.value)
    return successes / len(attempts)


def block_rate(attempts: list[dict]) -> float:
    if not attempts:
        return 0.0
    blocked = sum(1 for a in attempts if a["outcome"] in (Outcome.BLOCKED.value, Outcome.LOCKED.value))
    return blocked / len(attempts)


def time_to_detection(
    attempts: list[dict],
    alerts: list[dict],
    tolerance_s: float = 30.0,
) -> dict:
    """For each attempt, finds the earliest alert at/after it (within tolerance_s).
    Returns per-attempt deltas plus mean/median TTD across all matched attempts.
    """
    alert_times = sorted(_parse_alert_timestamp(a["timestamp"]) for a in alerts if "timestamp" in a)

    deltas: list[float] = []
    for attempt in attempts:
        attempt_time = datetime.fromisoformat(attempt["timestamp"])
        for alert_time in alert_times:
            delta = (alert_time - attempt_time).total_seconds()
            if 0 <= delta <= tolerance_s:
                deltas.append(delta)
                break

    return {
        "matched_attempts": len(deltas),
        "total_attempts": len(attempts),
        "detection_rate": (len(deltas) / len(attempts)) if attempts else 0.0,
        "mean_ttd_s": mean(deltas) if deltas else None,
        "median_ttd_s": median(deltas) if deltas else None,
    }
