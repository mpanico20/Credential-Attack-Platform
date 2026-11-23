"""Backend di risoluzione CAPTCHA (a innesto, come i backend browser).

Un solver trasforma un CaptchaTask (tipo + sitekey + URL pagina) in un token
che il form di login invia e che il server verifica col provider del CAPTCHA.

  - NoSolver        -> non risolve mai (token=None): l'attacco resta BLOCKED dal
                       CAPTCHA. E' la modalita' "misura la difesa".
  - CapSolverSolver -> chiama l'API CapSolver (createTask -> poll getTaskResult).

Scope (tesi): usare SOLO contro il portale di lab autorizzato, con la PROPRIA
chiave CapSolver e le PROPRIE sitekey. L'obiettivo e' MISURARE l'efficacia del
CAPTCHA (block rate) e il costo dell'arms-race del solver (bypass rate, latenza),
non aggirare CAPTCHA di terzi.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

import requests

TURNSTILE = "turnstile"
RECAPTCHA_V2 = "recaptcha_v2"
RECAPTCHA_V3 = "recaptcha_v3"


@dataclass
class CaptchaTask:
    type: str
    sitekey: str
    page_url: str
    is_invisible: bool = False
    action: str | None = None
    min_score: float | None = None


@dataclass
class CaptchaResult:
    success: bool
    token: str | None = None
    solve_time_ms: float | None = None
    error: str | None = None


class CaptchaSolver:
    """Interfaccia. solve() NON deve sollevare eccezioni: in caso di problemi
    ritorna CaptchaResult(success=False, error=...)."""
    name = "base"

    def solve(self, task: CaptchaTask) -> CaptchaResult:
        raise NotImplementedError


class NoSolver(CaptchaSolver):
    """Nessun solver: il CAPTCHA non viene mai risolto -> l'attacco e' bloccato.
    Modalita' "misura la difesa" (il ramo fingerprint camoufox/cdp passa comunque
    dal flusso browser; qui NoSolver significa solo: niente token da API)."""
    name = "none"

    def solve(self, task: CaptchaTask) -> CaptchaResult:
        return CaptchaResult(success=False, error="nessun solver configurato")


_CAPSOLVER_TASK = {
    TURNSTILE: "AntiTurnstileTaskProxyLess",
    RECAPTCHA_V2: "ReCaptchaV2TaskProxyLess",
    RECAPTCHA_V3: "ReCaptchaV3TaskProxyLess",
}


class CapSolverSolver(CaptchaSolver):
    """Risolve via API CapSolver: createTask -> poll getTaskResult."""
    name = "capsolver"
    API = "https://api.capsolver.com"

    def __init__(self, api_key: str, poll_timeout_s: float = 120.0,
                 poll_interval_s: float = 3.0):
        self.api_key = api_key
        self.poll_timeout_s = poll_timeout_s
        self.poll_interval_s = poll_interval_s

    def _task_payload(self, task: CaptchaTask) -> dict:
        t = _CAPSOLVER_TASK.get(task.type)
        if not t:
            raise ValueError(f"tipo CAPTCHA non supportato: {task.type}")
        payload = {"type": t, "websiteURL": task.page_url, "websiteKey": task.sitekey}
        if task.type == RECAPTCHA_V2:
            payload["isInvisible"] = bool(task.is_invisible)
        if task.type == RECAPTCHA_V3:
            payload["pageAction"] = task.action or "verify"
            if task.min_score is not None:
                payload["minScore"] = task.min_score
        return payload

    def solve(self, task: CaptchaTask) -> CaptchaResult:
        start = time.perf_counter()
        if not self.api_key:
            return CaptchaResult(success=False, error="chiave API CapSolver mancante")
        try:
            create = requests.post(
                f"{self.API}/createTask",
                json={"clientKey": self.api_key, "task": self._task_payload(task)},
                timeout=30,
            ).json()
        except Exception as exc:
            return CaptchaResult(success=False, error=f"createTask: {exc}")
        if create.get("errorId"):
            return CaptchaResult(success=False, error=f"createTask: {create.get('errorDescription', create)}")
        task_id = create.get("taskId")
        if not task_id:
            return CaptchaResult(success=False, error=f"createTask: nessun taskId ({create})")

        deadline = start + self.poll_timeout_s
        while time.perf_counter() < deadline:
            time.sleep(self.poll_interval_s)
            try:
                res = requests.post(
                    f"{self.API}/getTaskResult",
                    json={"clientKey": self.api_key, "taskId": task_id},
                    timeout=30,
                ).json()
            except Exception as exc:
                return CaptchaResult(success=False, error=f"getTaskResult: {exc}")
            if res.get("errorId"):
                return CaptchaResult(success=False, error=f"getTaskResult: {res.get('errorDescription', res)}")
            if res.get("status") == "ready":
                sol = res.get("solution", {}) or {}
                token = sol.get("token") or sol.get("gRecaptchaResponse")
                dt = (time.perf_counter() - start) * 1000
                if token:
                    return CaptchaResult(success=True, token=token, solve_time_ms=dt)
                return CaptchaResult(success=False, error=f"pronto ma senza token ({sol})", solve_time_ms=dt)
        return CaptchaResult(
            success=False, error="timeout attesa soluzione",
            solve_time_ms=(time.perf_counter() - start) * 1000,
        )


def make_solver(cfg) -> CaptchaSolver:
    """Factory dalla config captcha (usa cfg.solver / cfg.api_key / cfg.poll_timeout_s).
    La chiave API si prende, in ordine: da cfg.api_key, altrimenti dalla variabile
    d'ambiente CAPSOLVER_API_KEY (consigliato: NON mettere la chiave in config.yaml,
    che è tracciato da git). Il flag CLI --captcha-key ha la precedenza (va in cfg)."""
    name = (getattr(cfg, "solver", "none") or "none").lower()
    if name in ("none", "", "off"):
        return NoSolver()
    if name == "capsolver":
        api_key = (getattr(cfg, "api_key", "") or "") or os.environ.get("CAPSOLVER_API_KEY", "")
        return CapSolverSolver(
            api_key=api_key,
            poll_timeout_s=getattr(cfg, "poll_timeout_s", 120.0),
        )
    raise ValueError(f"solver sconosciuto: {name}")
