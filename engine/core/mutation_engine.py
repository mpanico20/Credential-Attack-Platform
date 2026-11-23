"""Credential tweaking: generates likely password variants from a base password
and optional user info (leet-speak substitutions, numeric/date suffixes, casing)."""
from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime

_LEET_MAP = {
    "a": "@",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "$",
}

_COMMON_SUFFIXES = ["1", "12", "123", "!", "1!", "01", "2024", "2025", "2026"]


def leet_variants(password: str) -> Iterator[str]:
    for char, sub in _LEET_MAP.items():
        if char in password.lower():
            yield password.replace(char, sub).replace(char.upper(), sub)


def suffix_variants(password: str) -> Iterator[str]:
    for suffix in _COMMON_SUFFIXES:
        yield f"{password}{suffix}"
    yield f"{password}{datetime.now().year}"


def case_variants(password: str) -> Iterator[str]:
    yield password.capitalize()
    yield password.upper()
    yield password.lower()


def mutate(password: str) -> list[str]:
    """Returns a deduplicated list of variants, base password included."""
    variants = {password}
    variants.update(leet_variants(password))
    variants.update(suffix_variants(password))
    variants.update(case_variants(password))
    return list(variants)
