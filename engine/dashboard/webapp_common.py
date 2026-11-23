"""Shared path setup for the GUI.

Importing this module locates the engine root (walking up to the folder with
main.py) and adds it to sys.path, so the engine's top-level modules (config,
models, attack_logging, ...) import cleanly regardless of how the GUI is started.
It also exposes the standard locations (configs/, logs/) used by the GUI.
"""
from __future__ import annotations

import sys
from pathlib import Path


def find_root() -> Path:
    """Engine root = nearest ancestor of this file that contains main.py."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "main.py").exists() and (parent / "config.py").exists():
            return parent
    return here.parent.parent


ROOT = find_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CONFIGS_DIR = ROOT / "configs"
MAIN_PY = ROOT / "main.py"
LOGS_DIRNAME = "logs"


def ensure_dirs() -> None:
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
