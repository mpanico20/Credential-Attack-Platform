"""Rilevamento + risoluzione del CAPTCHA nel flusso browser.

Data una sessione browser (con evaluate()), rileva il tipo di CAPTCHA presente,
ne estrae la sitekey (override da config se presente, altrimenti dal DOM) e, se
e' attivo un solver, ottiene il token e lo INIETTA nel form. Il server verifica
poi il token al submit.

Scope: solo contro il lab autorizzato (vedi captcha/solver.py).
"""
from __future__ import annotations

import json
import time

from captcha.solver import (CaptchaTask, NoSolver,
                            TURNSTILE, RECAPTCHA_V2, RECAPTCHA_V3)

_PRESENT_JS = {
    TURNSTILE: "!!(document.querySelector('.cf-turnstile')||document.querySelector('iframe[src*=\"challenges.cloudflare.com\"]'))",
    RECAPTCHA_V2: "!!(document.querySelector('.g-recaptcha')||document.querySelector('iframe[src*=\"/recaptcha/\"]'))",
}

_SITEKEY_JS = {
    TURNSTILE: "(document.querySelector('.cf-turnstile')&&document.querySelector('.cf-turnstile').getAttribute('data-sitekey'))||null",
    RECAPTCHA_V2: "(document.querySelector('.g-recaptcha')&&document.querySelector('.g-recaptcha').getAttribute('data-sitekey'))||(function(){var f=document.querySelector('iframe[src*=\"/recaptcha/\"]');if(!f)return null;var m=f.src.match(/[?&]k=([^&]+)/);return m?m[1]:null;})()",
}

_TOKEN_FIELD_JS = {
    TURNSTILE: "(document.querySelector('[name=\"cf-turnstile-response\"]')||{}).value||''",
    RECAPTCHA_V2: "(document.getElementById('g-recaptcha-response')||{}).value||''",
}

_INJECT_JS = {
    RECAPTCHA_V2: "(function(t){var el=document.getElementById('g-recaptcha-response');if(!el){el=document.createElement('textarea');el.id='g-recaptcha-response';el.name='g-recaptcha-response';el.style.display='none';(document.forms[0]||document.body).appendChild(el);}el.value=t;return true;})",
    TURNSTILE: "(function(t){var el=document.querySelector('[name=\"cf-turnstile-response\"]');if(!el){el=document.createElement('input');el.type='hidden';el.name='cf-turnstile-response';(document.forms[0]||document.body).appendChild(el);}el.value=t;return true;})",
}


def _detect_type(session, forced):
    """Tipo CAPTCHA: forzato da config (turnstile/recaptcha_v2/recaptcha_v3) o
    auto-rilevato dal DOM. v3 non ha widget DOM -> va forzato da config."""
    if forced and forced != "auto":
        return forced
    for ctype in (TURNSTILE, RECAPTCHA_V2):
        try:
            if session.evaluate(_PRESENT_JS[ctype]):
                return ctype
        except Exception:
            continue
    return None


def _get_sitekey(session, ctype, override):
    if override:
        return override
    js = _SITEKEY_JS.get(ctype)
    if not js:
        return None
    try:
        return session.evaluate(js)
    except Exception:
        return None


def _poll_auto_token(session, ctype, timeout_s):
    """Attende che il CAPTCHA invisible/managed si auto-completi (IP/fingerprint
    buoni): ritorna il token se il campo-risposta si popola entro timeout_s,
    altrimenti None (challenge interattiva o non superata)."""
    js = _TOKEN_FIELD_JS.get(ctype)
    if not js or timeout_s <= 0:
        return None
    deadline = time.perf_counter() + timeout_s
    while time.perf_counter() < deadline:
        try:
            v = session.evaluate(js)
        except Exception:
            v = None
        if v:
            return v
        time.sleep(0.5)
    return None


def handle_captcha(session, cfg, solver, page_url, sitekey_override=None):
    """Rileva e (se c'e' un solver) risolve il CAPTCHA, iniettando il token.

    Ritorna un dict:
      {present, type, sitekey, outcome, token, solve_time_ms, error}
    outcome: 'absent' | 'auto_passed' | 'blocked' | 'solved' | 'error'
      - absent     : nessun CAPTCHA sulla pagina
      - auto_passed: widget presente ma superato DA SOLO (IP/fingerprint buoni) -> si prosegue
      - blocked    : widget presente, non auto-superato, nessun solver -> l'attacco e' fermato
      - solved     : token ottenuto dal solver e iniettato nel form
      - error      : sitekey mancante / solver fallito / iniezione fallita
    """
    out = {"present": False, "type": None, "sitekey": None, "outcome": "absent",
           "token": None, "solve_time_ms": None, "error": None}

    ctype = _detect_type(session, getattr(cfg, "type", "auto"))
    if not ctype:
        return out
    out["present"] = True
    out["type"] = ctype

    auto_token = _poll_auto_token(session, ctype, float(getattr(cfg, "auto_wait_s", 6.0)))
    if auto_token:
        out["token"] = auto_token
        out["outcome"] = "auto_passed"
        return out

    if isinstance(solver, NoSolver) or getattr(solver, "name", "none") == "none":
        out["outcome"] = "blocked"
        return out

    inject = _INJECT_JS.get(ctype)
    if not inject:
        out["outcome"] = "error"
        out["error"] = f"iniezione non supportata per {ctype} (per ora Turnstile e reCAPTCHA v2)"
        return out
    sitekey = _get_sitekey(session, ctype, sitekey_override)
    out["sitekey"] = sitekey
    if not sitekey:
        out["outcome"] = "error"
        out["error"] = "sitekey non trovata (passa captcha_sitekey nel target)"
        return out

    task = CaptchaTask(
        type=ctype, sitekey=sitekey, page_url=page_url,
        is_invisible=bool(getattr(cfg, "invisible", False)),
        action=getattr(cfg, "action", None),
        min_score=getattr(cfg, "min_score", None),
    )
    res = solver.solve(task)
    out["solve_time_ms"] = res.solve_time_ms
    if not res.success or not res.token:
        out["outcome"] = "error"
        out["error"] = res.error or "solver fallito"
        return out

    try:
        session.evaluate(inject + "(" + json.dumps(res.token) + ")")
        out["token"] = res.token
        out["outcome"] = "solved"
    except Exception as exc:
        out["outcome"] = "error"
        out["error"] = f"iniezione token: {exc}"
    return out
