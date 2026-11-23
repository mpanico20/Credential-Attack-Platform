"""Plain wordlist loading (e.g. RockYou-derived subsets) for spray/brute-force."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


def load_wordlist(path: str | Path) -> Iterator[str]:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                yield word


def load_usernames(path: str | Path) -> list[str]:
    return list(load_wordlist(path))
