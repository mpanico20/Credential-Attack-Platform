"""Pandas-based aggregations over a run's attempt log, used by the dashboard."""
from __future__ import annotations

import pandas as pd

from models import Outcome


def to_dataframe(attempts: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(attempts)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def outcome_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    return df["outcome"].value_counts().rename_axis("outcome").reset_index(name="count")


def success_rate(df: pd.DataFrame) -> float:
    if df.empty:
        return 0.0
    return (df["outcome"] == Outcome.SUCCESS.value).mean()


def block_rate(df: pd.DataFrame) -> float:
    if df.empty:
        return 0.0
    return df["outcome"].isin([Outcome.BLOCKED.value, Outcome.LOCKED.value]).mean()


def attempts_over_time(df: pd.DataFrame, freq: str = "10s") -> pd.DataFrame:
    if df.empty:
        return df
    return (
        df.set_index("timestamp")
        .resample(freq)
        .size()
        .rename("attempts")
        .reset_index()
    )


def latency_stats(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"mean_ms": None, "p95_ms": None}
    return {
        "mean_ms": df["latency_ms"].mean(),
        "p95_ms": df["latency_ms"].quantile(0.95),
    }


def captcha_breakdown(df: pd.DataFrame) -> dict | None:
    """CAPTCHA outcomes for a run, or None when the campaign never hit a CAPTCHA.

    Esiti loggati dall'engine in `captcha_outcome`: absent|auto_passed|blocked|
    solved|error. "present" = il widget e' comparso (tutto tranne absent); il
    bypass rate = (solved + auto_passed)/present misura quanto l'attaccante supera
    il CAPTCHA, col solver o per auto-pass. Rispecchia analyze_logs.py."""
    if df.empty or "captcha_outcome" not in df.columns:
        return None
    outcomes = df["captcha_outcome"].dropna()
    if outcomes.empty:
        return None
    counts = outcomes.value_counts()

    def c(name: str) -> int:
        return int(counts.get(name, 0))

    solved, auto = c("solved"), c("auto_passed")
    blocked, error, absent = c("blocked"), c("error"), c("absent")
    present = solved + auto + blocked + error
    out = {
        "present": present,
        "absent": absent,
        "solved": solved,
        "auto_passed": auto,
        "blocked": blocked,
        "error": error,
        "bypass_rate": (solved + auto) / present if present else None,
    }
    if "solve_time_ms" in df.columns:
        solved_rows = df[df["captcha_outcome"] == "solved"]
        solve_ms = pd.to_numeric(solved_rows.get("solve_time_ms"), errors="coerce").dropna()
        out["solve_ms_avg"] = float(solve_ms.mean()) if not solve_ms.empty else None
    return out
