"""Minimal alert sink for new credential exposures - logs to file today,
swap `notify` for a webhook/email call once a destination is chosen."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path


def notify(message: str, output_dir: str | Path = "logs") -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    line = f"[{datetime.now().isoformat()}] {message}\n"
    with (output_dir / "alerts.log").open("a", encoding="utf-8") as f:
        f.write(line)
