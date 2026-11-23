"""Password spraying: a small set of common passwords tried across many
usernames, to stay under per-account lockout thresholds."""
from __future__ import annotations

from data.wordlists import load_wordlist
from core.attack_engine import AttackEngine
from models import AttackType, AttemptResult, Credential, Target


def run(
    engine: AttackEngine,
    target: Target,
    usernames_path: str,
    passwords_path: str,
    apply_mutation: bool = True,
) -> list[AttemptResult]:
    usernames = list(load_wordlist(usernames_path))
    passwords = list(load_wordlist(passwords_path))

    credentials = (
        Credential(username=user, password=pwd, source="spray")
        for pwd in passwords
        for user in usernames
    )
    return engine.run(target, credentials, AttackType.PASSWORD_SPRAY, apply_mutation)
