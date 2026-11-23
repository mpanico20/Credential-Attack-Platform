"""SSH password login attempts (e.g. against a Linux host or network device).

No browser involved - CDP mode doesn't apply to SSH, so this uses paramiko
directly, mirroring core.ldap_attack. Only password auth is tested: key auth
and the SSH agent are disabled so a positive result means the *password* worked.

Outcome mapping:
  * authenticated                       -> SUCCESS
  * server rejected the password        -> FAILURE
  * server demands another factor       -> FAILURE (metadata mfa_required=True):
      the password may be right but a second factor / different method is needed,
      analogous to "MFA required" on OAuth.
  * cannot reach / connection dropped   -> ERROR (see note)

Note on fail2ban / MaxAuthTries: an IP ban shows up as the connection timing
out or being refused (packets dropped), i.e. an ERROR here, not a FAILURE. We
keep it ERROR at the adapter level (honest: a first-attempt network glitch looks
the same) and let the backoff/analysis layer flag *repeated* ERRORs after
earlier successes as a probable ban - the same heuristic AttackEngine already
uses to retire a dead proxy.
"""
from __future__ import annotations

import socket
import time

import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    BadAuthenticationType,
    NoValidConnectionsError,
    PartialAuthentication,
    SSHException,
)

from models import Credential, Outcome, Target

_CONNECT_TIMEOUT_S = 10


def attempt_login(
    target: Target, credential: Credential
) -> tuple[Outcome, float, str | None, dict]:
    start = time.perf_counter()
    error: str | None = None
    meta: dict = {}
    host = target.ssh_host or target.base_url
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=target.ssh_port,
            username=credential.username,
            password=credential.password,
            timeout=_CONNECT_TIMEOUT_S,
            auth_timeout=_CONNECT_TIMEOUT_S,
            banner_timeout=_CONNECT_TIMEOUT_S,
            look_for_keys=False,
            allow_agent=False,
        )
        outcome = Outcome.SUCCESS
    except (AuthenticationException, BadAuthenticationType) as exc:
        outcome = Outcome.FAILURE
        error = str(exc)
    except PartialAuthentication as exc:
        outcome = Outcome.FAILURE
        error = str(exc)
        meta = {"mfa_required": True}
    except (NoValidConnectionsError, socket.timeout, socket.error, SSHException) as exc:
        outcome = Outcome.ERROR
        error = str(exc)
    except Exception as exc:
        outcome = Outcome.ERROR
        error = str(exc)
    finally:
        try:
            client.close()
        except Exception:
            pass

    latency_ms = (time.perf_counter() - start) * 1000
    return outcome, latency_ms, error, meta
