"""Credential stuffing: replay a leaked combo list 1:1 against a target."""
from __future__ import annotations

from core.attack_engine import AttackEngine
from data.combo_loader import load_combo_list
from models import AttackType, AttemptResult, Target


def run(engine: AttackEngine, target: Target, combo_list_path: str) -> list[AttemptResult]:
    credentials = load_combo_list(combo_list_path)
    return engine.run(target, credentials, AttackType.CREDENTIAL_STUFFING, apply_mutation=False)
