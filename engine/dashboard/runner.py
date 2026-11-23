"""Launch engine attack runs as subprocesses from the GUI.

Each run is `python main.py --config <cfg> attack ...` started with Popen (cwd =
engine root) and never waited on, so several runs can be in flight at once. A
registry keyed by run_id keeps the handles for the GUI process's lifetime, which
is what lets the panel show them all. The subprocess stdout is streamed to
logs/<run_id>.console.log for the GUI to tail; the engine's structured JSONL
log (logs/attacks-<run_id>.jsonl) is written separately by the engine itself.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from dashboard.webapp_common import ROOT, LOGS_DIRNAME

ATTACK_TYPES = ["stuffing", "spray", "bruteforce"]


class RunSpecError(ValueError):
    """Raised when the parameters for a run are incomplete/invalid."""


@dataclass
class RunSpec:
    config_path: Path
    target: str
    attack_type: str
    combo_list: str | None = None
    usernames: str | None = None
    passwords: str | None = None
    username: str | None = None
    mutation: bool = False
    use_proxy: bool = False
    defense_config: str | None = None
    evasion_config: str | None = None
    captcha_type: str | None = None
    captcha_solver: str | None = None
    captcha_key: str | None = None
    exploit_on_success: bool = False
    exploit_base_url: str | None = None
    exploit_lhost: str | None = None
    exploit_lport: int | None = None
    exploit_payload: str | None = None
    run_id: str | None = None

    def resolved_run_id(self) -> str:
        if self.run_id:
            return self.run_id
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"web_{self.target}_{self.attack_type}_{stamp}"

    def build_argv(self, python: str | None = None) -> list[str]:
        """The full command line, with required-field validation per attack type."""
        py = python or sys.executable
        cfg = str(self.config_path)
        argv = [py, "main.py", "--config", cfg, "attack",
                "--target", self.target, "--attack-type", self.attack_type]

        if self.attack_type == "stuffing":
            if not self.combo_list:
                raise RunSpecError("stuffing richiede una combo-list.")
            argv += ["--combo-list", self.combo_list]
        elif self.attack_type == "spray":
            if not (self.usernames and self.passwords):
                raise RunSpecError("spray richiede file usernames e passwords.")
            argv += ["--usernames", self.usernames, "--passwords", self.passwords]
        elif self.attack_type == "bruteforce":
            if not (self.username and self.passwords):
                raise RunSpecError("bruteforce richiede username e file passwords.")
            argv += ["--username", self.username, "--passwords", self.passwords]
        else:
            raise RunSpecError(f"attack-type sconosciuto: {self.attack_type}")

        if self.mutation and self.attack_type in ("spray", "bruteforce"):
            argv.append("--mutation")
        if self.use_proxy:
            argv.append("--use-proxy")
        argv += ["--run-id", self.resolved_run_id()]
        if self.defense_config:
            argv += ["--defense-config", self.defense_config]
        if self.evasion_config:
            argv += ["--evasion-config", self.evasion_config]

        if self.captcha_type:
            argv += ["--captcha-type", self.captcha_type]
        if self.captcha_solver:
            argv += ["--captcha-solver", self.captcha_solver]
        if self.captcha_key:
            argv += ["--captcha-key", self.captcha_key]

        if self.exploit_on_success:
            argv.append("--exploit-on-success")
            if self.exploit_base_url:
                argv += ["--exploit-base-url", self.exploit_base_url]
            if self.exploit_lhost:
                argv += ["--exploit-lhost", self.exploit_lhost]
            if self.exploit_lport:
                argv += ["--exploit-lport", str(self.exploit_lport)]
            if self.exploit_payload:
                argv += ["--exploit-payload", self.exploit_payload]
        return argv


@dataclass
class RunHandle:
    run_id: str
    argv: list[str]
    console_path: Path
    proc: subprocess.Popen = field(repr=False)
    started_at: datetime = field(default_factory=datetime.now)
    log_file: object = field(default=None, repr=False)

    @property
    def status(self) -> str:
        rc = self.proc.poll()
        if rc is None:
            return "running"
        return "done" if rc == 0 else "failed"

    @property
    def returncode(self) -> int | None:
        return self.proc.poll()

    def read_console(self, max_chars: int = 20000) -> str:
        try:
            text = self.console_path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return ""
        return text[-max_chars:]

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()

    def _close_log(self) -> None:
        if self.log_file is not None:
            try:
                self.log_file.close()
            except Exception:
                pass
            self.log_file = None


_REGISTRY: dict[str, RunHandle] = {}


def launch(spec: RunSpec, python: str | None = None) -> RunHandle:
    argv = spec.build_argv(python)
    run_id = spec.resolved_run_id()

    console_dir = ROOT / LOGS_DIRNAME
    console_dir.mkdir(parents=True, exist_ok=True)
    console_path = console_dir / f"{run_id}.console.log"

    log_file = open(console_path, "w", encoding="utf-8")
    log_file.write(f"$ {' '.join(argv)}\n\n")
    log_file.flush()

    proc = subprocess.Popen(
        argv,
        cwd=str(ROOT),
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
    )
    handle = RunHandle(
        run_id=run_id, argv=argv, console_path=console_path, proc=proc, log_file=log_file
    )
    _REGISTRY[run_id] = handle
    return handle


def get(run_id: str) -> RunHandle | None:
    return _REGISTRY.get(run_id)


def all_runs() -> list[RunHandle]:
    for h in _REGISTRY.values():
        if h.proc.poll() is not None and h.log_file is not None:
            h._close_log()
    return sorted(_REGISTRY.values(), key=lambda h: h.started_at, reverse=True)


def remove(run_id: str) -> None:
    """Drop a finished run from the registry (does not touch the log files).
    A still-running process is terminated first so we don't leak it."""
    handle = _REGISTRY.pop(run_id, None)
    if handle is not None:
        handle.stop()
        handle._close_log()
