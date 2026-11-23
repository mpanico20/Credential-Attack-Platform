"""Maps platform attack modules to MITRE ATT&CK techniques (tactic TA0001 - Initial Access),
used to tag AttemptResult.technique_id for TTP-based reporting (e.g. TA505 emulation)."""
from __future__ import annotations

from models import AttackType

TECHNIQUE_MAP: dict[AttackType, str] = {
    AttackType.CREDENTIAL_STUFFING: "T1110.004",
    AttackType.PASSWORD_SPRAY: "T1110.003",
    AttackType.BRUTE_FORCE: "T1110.001",
}

TECHNIQUE_NAMES: dict[str, str] = {
    "T1110.004": "Credential Stuffing",
    "T1110.003": "Password Spraying",
    "T1110.001": "Password Guessing",
}


def technique_for(attack_type: AttackType) -> str:
    return TECHNIQUE_MAP[attack_type]
