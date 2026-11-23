"""Brute force: a wordlist tried against a single target account, low-and-slow
paced by AttackEngine's RateLimiter to evade lockout policies."""
from __future__ import annotations

from data.wordlists import load_wordlist
from core.attack_engine import AttackEngine
from models import AttackType, AttemptResult, Credential, Target


def run(
    engine: AttackEngine,
    target: Target,
    username: str,
    passwords_path: str,
    apply_mutation: bool = True,
) -> list[AttemptResult]:
    credentials = (
        Credential(username=username, password=pwd, source="wordlist")
        for pwd in load_wordlist(passwords_path)
    )
    return engine.run(target, credentials, AttackType.BRUTE_FORCE, apply_mutation)
