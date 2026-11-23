"""Parses combo lists in the common leak formats:
  email:pass
  user:pass
  url|email|pass
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from models import Credential


def _parse_line(line: str) -> Credential | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "|" in line:
        parts = line.split("|")
        if len(parts) >= 3:
            _url, user, password = parts[0], parts[1], parts[2]
            return Credential(username=user, password=password, source="combo")
        return None

    if ":" in line:
        user, _, password = line.partition(":")
        if user and password:
            return Credential(username=user, password=password, source="combo")

    return None


def load_combo_list(path: str | Path) -> Iterator[Credential]:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            cred = _parse_line(line)
            if cred:
                yield cred
