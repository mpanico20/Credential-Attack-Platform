"""Estrae le metriche di una campagna dai log JSONL dell'engine.

Ogni run dell'engine scrive un file `logs/attacks-<run_id>.jsonl` (una riga per
tentativo). Questo script calcola, per ogni file, le metriche che servono alle
tabelle della tesi; con piu' file (ripetizioni della stessa condizione) calcola
anche media +/- deviazione standard.

Uso:
    python analyze_logs.py logs/attacks-R1.jsonl
    python analyze_logs.py --valid 5 logs/attacks-R1.jsonl
    python analyze_logs.py --valid 5 --aggregate logs/*.jsonl
    python analyze_logs.py --valid 5 --aggregate --csv tabella.csv logs/*.jsonl

Con --aggregate i file vengono RAGGRUPPATI per cella sperimentale
(attack_type x defense_config x evasion_config) leggendo i tag di ogni log: per
ogni cella si riporta media +/- IC95 (t di Student, adatto a N piccolo) e, per le
proporzioni (recall, block_rate, ...), il tasso POOLATO con IC95 di Wilson.
Con --csv l'aggregato per cella viene scritto anche in formato tabellare (una
riga per cella x metrica), pronto per le tabelle della tesi.

Metriche (per file):
  - tentativi totali e conteggio per esito (SUCCESS/FAILURE/LOCKED/BLOCKED/ERROR)
  - success rate / recall (se --valid N: successi / N credenziali valide)
  - block rate = (LOCKED reali + BLOCKED) / INVIATI, con inviati = totale - skip
    (gli skip da cooldown sono comportamento dell'attaccante, non blocchi del
    target, quindi esclusi da numeratore E denominatore; ERROR a parte)
  - ATD (attempts-to-block): posizione del PRIMO blocco reale (in ordine di tempo)
  - throughput (tentativi/min) e wall time
  - n. identita' usate (per target browser) e ritardo medio applicato
  - skip per cooldown (LOCKED generati dall'engine, non nuovi blocchi del target)
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import statistics
from collections import OrderedDict
from datetime import datetime
from pathlib import Path


_T95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
    8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
    15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086, 21: 2.080,
    22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056, 27: 2.052, 28: 2.048,
    29: 2.045, 30: 2.042,
}


def _t95(df: int) -> float:
    if df <= 0:
        return float("nan")
    if df in _T95:
        return _T95[df]
    return 1.960


def t_ci(vals: list[float]) -> tuple[float, float, float, int]:
    """Media e semi-ampiezza dell'IC 95% (t di Student) di un campione.

    Ritorna (media, semiampiezza, std_campionaria, n). Con n<2 la semiampiezza e
    la std sono NaN (non stimabili): si riporta solo la media.
    """
    n = len(vals)
    mean = statistics.mean(vals) if n else float("nan")
    if n < 2:
        return mean, float("nan"), float("nan"), n
    s = statistics.stdev(vals)
    half = _t95(n - 1) * s / math.sqrt(n)
    return mean, half, s, n


def wilson_ci(num: int, den: int, z: float = 1.960) -> tuple[float, float, float]:
    """IC di Wilson al 95% per una proporzione (num successi su den prove).

    Piu' corretto dell'IC normale per proporzioni e con denominatori piccoli, e
    non sbrodola mai fuori da [0,1]. Ritorna (p, lo, hi) in frazione [0,1].
    """
    if den <= 0:
        return float("nan"), float("nan"), float("nan")
    num = min(max(num, 0), den)
    p = num / den
    z2 = z * z
    denom = 1 + z2 / den
    center = (p + z2 / (2 * den)) / denom
    half = z * math.sqrt(p * (1 - p) / den + z2 / (4 * den * den)) / denom
    lo = max(0.0, center - half)
    hi = min(1.0, center + half)
    return p, lo, hi


_CONT_METRICS = [
    "ATD", "throughput_per_min", "wall_time_s", "n_identities",
    "avg_delay_ms", "captcha_solve_ms_avg",
]

_PROP_METRICS = [
    ("success_rate_%", ("success",), "total"),
    ("recall_%", ("success",), "_n_valid"),
    ("block_rate_%", ("locked", "blocked"), "sent"),
    ("error_rate_%", ("error",), "total"),
    ("captcha_bypass_rate_%", ("captcha_solved", "captcha_auto_passed"), "captcha_present"),
]


def load(path: str) -> list[dict]:
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def _ts(e: dict):
    try:
        return datetime.fromisoformat(e["timestamp"])
    except Exception:
        return None


def metrics(entries: list[dict], n_valid: int | None = None) -> dict:
    total = len(entries)
    if total == 0:
        return {"total": 0}

    def n(outcome):
        return sum(1 for e in entries if e.get("outcome") == outcome)

    succ, fail, error = n("success"), n("failure"), n("error")
    skipped = sum(1 for e in entries if e.get("skipped") is True)
    locked = sum(
        1 for e in entries if e.get("outcome") == "locked" and not e.get("skipped")
    )
    blocked = n("blocked")

    sent = total - skipped
    block_rate = (locked + blocked) / sent * 100 if sent > 0 else 0.0
    error_rate = error / total * 100

    ordered = [e for e in entries if _ts(e) is not None]
    ordered.sort(key=lambda e: _ts(e))
    atd = None
    for i, e in enumerate(ordered, start=1):
        if e.get("outcome") in ("locked", "blocked") and not e.get("skipped"):
            atd = i
            break

    wall_s = None
    thr = None
    if len(ordered) >= 2:
        wall_s = (_ts(ordered[-1]) - _ts(ordered[0])).total_seconds()
        if wall_s > 0:
            thr = total / (wall_s / 60.0)

    n_identities = sum(1 for e in entries if e.get("identity_attempt") == 1) or None

    delays = [e.get("delay_applied_ms") for e in entries if isinstance(e.get("delay_applied_ms"), (int, float))]
    avg_delay_ms = statistics.mean(delays) if delays else None

    cap = {}
    cap_outcomes = [e.get("captcha_outcome") for e in entries if e.get("captcha_outcome")]
    if cap_outcomes:
        def cn(o):
            return sum(1 for x in cap_outcomes if x == o)
        c_solved, c_auto = cn("solved"), cn("auto_passed")
        c_blocked, c_error, c_absent = cn("blocked"), cn("error"), cn("absent")
        present = c_solved + c_auto + c_blocked + c_error
        solve_ms = [e.get("solve_time_ms") for e in entries
                    if e.get("captcha_outcome") == "solved"
                    and isinstance(e.get("solve_time_ms"), (int, float))]
        cap = {
            "captcha_present": present,
            "captcha_absent": c_absent,
            "captcha_solved": c_solved,
            "captcha_auto_passed": c_auto,
            "captcha_blocked": c_blocked,
            "captcha_error": c_error,
            "captcha_bypass_rate_%": round((c_solved + c_auto) / present * 100, 1) if present else None,
            "captcha_solve_ms_avg": round(statistics.mean(solve_ms), 0) if solve_ms else None,
        }

    out = {
        "total": total,
        "sent": sent,
        "success": succ, "failure": fail, "locked": locked,
        "blocked": blocked, "error": error, "skipped_cooldown": skipped,
        "success_rate_%": round(succ / total * 100, 1),
        "block_rate_%": round(block_rate, 1),
        "error_rate_%": round(error_rate, 1),
        "ATD": atd,
        "wall_time_s": round(wall_s, 1) if wall_s is not None else None,
        "throughput_per_min": round(thr, 1) if thr is not None else None,
        "n_identities": n_identities,
        "avg_delay_ms": round(avg_delay_ms, 0) if avg_delay_ms is not None else None,
    }
    if n_valid:
        out["recall_%"] = round(succ / n_valid * 100, 1)
        out["valid_found"] = f"{succ}/{n_valid}"
    out.update(cap)
    return out


def tags_of(entries: list[dict]) -> dict:
    """Legge i tag di run (attack_type/run_id/defense_config/evasion_config)."""
    if not entries:
        return {}
    e0 = entries[0]
    keys = ("attack_type", "run_id", "defense_config", "evasion_config")
    return {k: e0[k] for k in keys if e0.get(k) is not None}


_CELL_DIMS = ("attack_type", "defense_config", "evasion_config")


def cell_key(tags: dict) -> tuple:
    return tuple(tags.get(d, "-") for d in _CELL_DIMS)


def print_file(path: str, m: dict, tags: dict | None = None) -> None:
    print("=" * 60)
    print("FILE:", path)
    if tags:
        print("  " + "  ".join(f"{k}={v}" for k, v in tags.items()))
    if m.get("total", 0) == 0:
        print("  (vuoto)")
        return
    order = [
        "total", "sent", "success", "failure", "locked", "blocked", "error",
        "skipped_cooldown", "success_rate_%", "recall_%", "valid_found",
        "block_rate_%", "error_rate_%", "ATD", "throughput_per_min",
        "wall_time_s", "n_identities", "avg_delay_ms",
        "captcha_present", "captcha_absent", "captcha_solved",
        "captcha_auto_passed", "captcha_blocked", "captcha_error",
        "captcha_bypass_rate_%", "captcha_solve_ms_avg",
    ]
    for k in order:
        if k in m and m[k] is not None:
            print(f"  {k:20s}: {m[k]}")


def aggregate_cell(ms: list[dict]) -> list[dict]:
    """Aggrega le run di UNA cella. Ritorna una riga per metrica con:
    media, IC-t (semiampiezza), std, n   e, per le proporzioni, il tasso
    poolato con IC di Wilson (lo/hi). Valori in NaN = non calcolabili.
    """
    rows: list[dict] = []
    ms = [m for m in ms if m.get("total", 0) > 0]

    for label, num_keys, den_key in _PROP_METRICS:
        per_run = [m[label] for m in ms if isinstance(m.get(label), (int, float))]
        if not per_run:
            continue
        mean, half, s, n = t_ci(per_run)
        num_sum = sum(sum(m.get(k, 0) or 0 for k in num_keys) for m in ms)
        den_sum = sum((m.get(den_key, 0) or 0) for m in ms)
        p, lo, hi = wilson_ci(int(num_sum), int(den_sum))
        rows.append({
            "metric": label, "kind": "proportion", "n": n,
            "mean": mean, "ci_half": half, "std": s,
            "pooled_%": p * 100 if den_sum else float("nan"),
            "pooled_lo_%": lo * 100 if den_sum else float("nan"),
            "pooled_hi_%": hi * 100 if den_sum else float("nan"),
            "pooled_num": int(num_sum), "pooled_den": int(den_sum),
        })

    for label in _CONT_METRICS:
        vals = [m[label] for m in ms if isinstance(m.get(label), (int, float))]
        if not vals:
            continue
        mean, half, s, n = t_ci(vals)
        rows.append({
            "metric": label, "kind": "continuous", "n": n,
            "mean": mean, "ci_half": half, "std": s,
            "pooled_%": float("nan"), "pooled_lo_%": float("nan"),
            "pooled_hi_%": float("nan"), "pooled_num": None, "pooled_den": None,
        })
    return rows


def _fmt(x) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "n/d"
    return f"{x:.1f}"


def print_cells(cells: "OrderedDict[tuple, list[dict]]") -> None:
    print("\n" + "#" * 64)
    print(f"AGGREGATO per cella  ({len(cells)} celle)  --  media +/- IC95(t); "
          "pooled = tasso complessivo con IC95 di Wilson")
    print("#" * 64)
    for key, rows in cells.items():
        tagstr = "  ".join(f"{d}={v}" for d, v in zip(_CELL_DIMS, key))
        n = max((r["n"] for r in rows), default=0)
        print("\n" + "-" * 64)
        print(f"{tagstr}   (n={n})")
        for r in rows:
            name = r["metric"]
            if r["n"] >= 2:
                base = f"{_fmt(r['mean'])} +/- {_fmt(r['ci_half'])}"
            else:
                base = f"{_fmt(r['mean'])} (n={r['n']}, IC n/d)"
            if r["kind"] == "proportion" and not math.isnan(r["pooled_%"]):
                pool = (f"  | pooled {_fmt(r['pooled_%'])} "
                        f"[{_fmt(r['pooled_lo_%'])}..{_fmt(r['pooled_hi_%'])}], "
                        f"{r['pooled_num']}/{r['pooled_den']}")
            else:
                pool = ""
            print(f"  {name:24s}: {base}{pool}")


def write_csv(cells: "OrderedDict[tuple, list[dict]]", path: str) -> None:
    cols = ["attack_type", "defense_config", "evasion_config", "metric", "kind",
            "n", "mean", "ci_half", "ci_low", "ci_high", "std",
            "pooled_pct", "pooled_lo_pct", "pooled_hi_pct", "pooled_num", "pooled_den"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for key, rows in cells.items():
            tags = dict(zip(_CELL_DIMS, key))
            for r in rows:
                mean, half = r["mean"], r["ci_half"]
                lo = mean - half if not math.isnan(half) else ""
                hi = mean + half if not math.isnan(half) else ""

                def _c(x):
                    return "" if (x is None or (isinstance(x, float) and math.isnan(x))) else round(x, 2)

                w.writerow({
                    "attack_type": tags["attack_type"],
                    "defense_config": tags["defense_config"],
                    "evasion_config": tags["evasion_config"],
                    "metric": r["metric"], "kind": r["kind"], "n": r["n"],
                    "mean": _c(mean), "ci_half": _c(half),
                    "ci_low": _c(lo if lo != "" else float("nan")),
                    "ci_high": _c(hi if hi != "" else float("nan")),
                    "std": _c(r["std"]),
                    "pooled_pct": _c(r["pooled_%"]),
                    "pooled_lo_pct": _c(r["pooled_lo_%"]),
                    "pooled_hi_pct": _c(r["pooled_hi_%"]),
                    "pooled_num": r["pooled_num"] if r["pooled_num"] is not None else "",
                    "pooled_den": r["pooled_den"] if r["pooled_den"] is not None else "",
                })
    print(f"\nCSV scritto: {path}  ({sum(len(r) for r in cells.values())} righe)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="file .jsonl o glob (es. logs/attacks-R1-*.jsonl)")
    ap.add_argument("--valid", type=int, default=None, help="n. credenziali valide piazzate (per il recall)")
    ap.add_argument("--aggregate", action="store_true", help="aggrega per cella (media +/- IC95 + pooled)")
    ap.add_argument("--csv", type=str, default=None, help="scrive l'aggregato per cella in un CSV")
    args = ap.parse_args()

    files = []
    for p in args.paths:
        files.extend(sorted(glob.glob(p)) or [p])

    groups: "OrderedDict[tuple, list[dict]]" = OrderedDict()
    for path in files:
        if not Path(path).exists():
            print("!! non trovato:", path)
            continue
        entries = load(path)
        m = metrics(entries, n_valid=args.valid)
        m["_n_valid"] = args.valid
        tags = tags_of(entries)
        print_file(path, m, tags)
        groups.setdefault(cell_key(tags), []).append(m)

    if args.aggregate or args.csv:
        cells: "OrderedDict[tuple, list[dict]]" = OrderedDict(
            (key, aggregate_cell(ms)) for key, ms in groups.items()
        )
        if args.aggregate:
            print_cells(cells)
        if args.csv:
            write_csv(cells, args.csv)


if __name__ == "__main__":
    main()
