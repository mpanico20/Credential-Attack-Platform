"""Structured JSONL logging of every attack attempt, one file per run.
Read back by the dashboard and by the SIEM correlator."""
from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path

from models import AttemptResult


class AttackLogger:
    def __init__(
        self,
        output_dir: str | Path,
        run_id: str | None = None,
        run_tags: dict | None = None,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = self.output_dir / f"attacks-{self.run_id}.jsonl"
        self.run_tags = dict(run_tags or {})
        self._lock = threading.Lock()

    def log(self, result: AttemptResult) -> None:
        d = result.to_dict()
        d["run_id"] = self.run_id
        if self.run_tags:
            d.update(self.run_tags)
        line = json.dumps(d, ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


def load_run(path: str | Path) -> list[dict]:
    path = Path(path)
    entries = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def list_runs(output_dir: str | Path) -> list[Path]:
    output_dir = Path(output_dir)
    if not output_dir.exists():
        return []
    return sorted(output_dir.glob("attacks-*.jsonl"), reverse=True)
