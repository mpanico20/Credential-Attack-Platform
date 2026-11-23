"""LDAP bind attempts (e.g. against Active Directory). No browser involved -
CDP mode doesn't apply to a directory protocol, so this uses ldap3 directly."""
from __future__ import annotations

import time

from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPException

from models import Credential, Outcome, Target


def attempt_bind(
    target: Target, credential: Credential
) -> tuple[Outcome, float, str | None, dict]:
    start = time.perf_counter()
    error = None
    user_dn = target.ldap_user_dn_template.format(
        username=credential.username, base_dn=target.ldap_base_dn
    )
    try:
        server = Server(target.ldap_server, get_info=ALL)
        conn = Connection(server, user=user_dn, password=credential.password)
        if conn.bind():
            outcome = Outcome.SUCCESS
            conn.unbind()
        else:
            outcome = Outcome.FAILURE
            error = conn.result.get("description") if conn.result else None
    except LDAPException as exc:
        outcome = Outcome.ERROR
        error = str(exc)

    latency_ms = (time.perf_counter() - start) * 1000
    return outcome, latency_ms, error, {}
