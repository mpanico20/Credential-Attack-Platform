"""Harness comparativo dei backend browser su suite pubbliche di fingerprinting.

Confronta TRE varianti, ognuna eseguita --repeat volte (media delle risorse +
stabilita dei verdetti):
  * cdp        : SeleniumBase CDP, spoof GPU OFF (espone la GPU reale dell'host)
  * cdp-spoof  : SeleniumBase CDP, spoof GPU ON  (spoofa le stringhe GPU nel MAIN
                 thread; il worker vede la GPU reale -> incoerenza attesa)
  * camoufox   : backend Camoufox (spoofing C++, coerente anche nei worker)

Metriche (richieste dal relatore):
  1. detection rate      -> verdetti delle suite (isBot, ecc.)
  2. coerenza fingerprint (worker inclusi) -> confronto main-thread vs Web Worker
     (ua/platform/hardwareConcurrency/WebGL vendor+renderer), calcolato da noi.
  3. consumo risorse     -> tempo di avvio + RAM (RSS), mediati su --repeat run.
  4. success rate        -> separato, dalle run reali dell'engine (`main.py attack`).

I probe avvolgono le VERE CDPSession/CamoufoxSession (misura i backend come li usa
l'engine). ESEGUI TU da .venv-c:
    .venv-c\\Scripts\\python.exe compare_backends.py --backend all --repeat 3 --headless
    .venv-c\\Scripts\\python.exe compare_backends.py --backend cdp,cdp-spoof   # sottoinsieme
    .venv-c\\Scripts\\python.exe compare_backends.py --backend camoufox --camoufox-os macos
Suite di detection:
  * deviceinfo (deviceandbrowserinfo.com) -> verdetto parsato (isBot + flag)
  * amiabot (amiabot.app)                 -> verdetto parsato (classification/risk/
    score + conteggio incoerenze); SECONDA fonte indipendente -> triangolazione
  * sannysoft (bot.sannysoft.com)         -> SOLO screenshot (prova visiva della
    superficie "tutto verde"); non testa i worker, quindi non distingue cdp-spoof.
Output: tabella aggregata + compare_out/compare_result.json + screenshot sannysoft
(solo 1a run).
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import time
from pathlib import Path

import psutil

from config import load_config

OUTDIR = Path(__file__).resolve().parent / "compare_out"
OUTDIR.mkdir(exist_ok=True)

DEVICEINFO_URL = "https://deviceandbrowserinfo.com/are_you_a_bot"
AMIABOT_URL = "https://amiabot.app/"
SCREENSHOT_SUITES = [
    ("sannysoft", "https://bot.sannysoft.com/"),
]

MAIN_JS = r'''({
  ua: navigator.userAgent,
  platform: navigator.platform,
  hardwareConcurrency: navigator.hardwareConcurrency,
  webdriver: navigator.webdriver,
  languages: (navigator.languages||[]).join(','),
  webglVendor: (function(){try{var c=document.createElement('canvas');var g=c.getContext('webgl')||c.getContext('experimental-webgl');var e=g.getExtension('WEBGL_debug_renderer_info');return g.getParameter(e.UNMASKED_VENDOR_WEBGL);}catch(e){return null;}})(),
  webglRenderer: (function(){try{var c=document.createElement('canvas');var g=c.getContext('webgl')||c.getContext('experimental-webgl');var e=g.getExtension('WEBGL_debug_renderer_info');return g.getParameter(e.UNMASKED_RENDERER_WEBGL);}catch(e){return null;}})()
})'''

WORKER_INJECT_JS = r'''(function(){ window.__wr=null; try{
  var code = "self.onmessage=function(){var v=null,r=null;try{var c=new OffscreenCanvas(1,1);var g=c.getContext('webgl');var e=g.getExtension('WEBGL_debug_renderer_info');v=g.getParameter(e.UNMASKED_VENDOR_WEBGL);r=g.getParameter(e.UNMASKED_RENDERER_WEBGL);}catch(err){}postMessage({ua:navigator.userAgent,platform:navigator.platform,hardwareConcurrency:navigator.hardwareConcurrency,webglVendor:v,webglRenderer:r});};";
  var b=new Blob([code],{type:'application/javascript'});
  var w=new Worker(URL.createObjectURL(b));
  w.onmessage=function(ev){ window.__wr=ev.data; };
  w.postMessage('go');
}catch(err){ window.__wr={error:String(err)}; } return true; })()'''

DEVICEINFO_FLAGS = (
    "isBot", "hasInconsistentWorkerValues", "isAutomatedWithCDP",
    "isHeadlessChrome", "hasInconsistentClientHints", "isWebGLInconsistent",
    "hasInconsistentGPUFeatures",
)


class CDPProbe:
    browser_names = ("chrome",)

    def __init__(self, cfg, label, spoof_gpu=False):
        self.cfg = cfg
        self.label = label
        self.spoof_gpu = spoof_gpu
        self.session = None
        self.launch_time_s = None

    def __enter__(self):
        from browser.cdp_session import CDPSession
        t0 = time.perf_counter()
        self.session = CDPSession(self.cfg.browser, proxy=None, spoof_gpu=self.spoof_gpu)
        self.session.__enter__()
        self.launch_time_s = time.perf_counter() - t0
        return self

    def __exit__(self, *a):
        if self.session:
            try:
                self.session.__exit__(None, None, None)
            except Exception:
                pass

    def goto(self, url):
        self.session.driver.open(url)

    def text(self):
        try:
            return self.session.driver.get_text("body") or ""
        except Exception:
            return ""

    def evaluate(self, js):
        return self.session.driver.evaluate(js)

    def screenshot(self, path):
        try:
            self.session.driver.save_screenshot(os.path.basename(path), folder=str(OUTDIR))
        except Exception as e:
            print("     (screenshot cdp fallito:", e, ")")


class CamoufoxProbe:
    browser_names = ("camoufox", "firefox")

    def __init__(self, cfg, label):
        self.cfg = cfg
        self.label = label
        self.session = None
        self.launch_time_s = None

    def __enter__(self):
        from browser.camoufox_session import CamoufoxSession
        t0 = time.perf_counter()
        self.session = CamoufoxSession(self.cfg.browser, self.cfg.camoufox, proxy=None)
        self.session.__enter__()
        self.launch_time_s = time.perf_counter() - t0
        return self

    def __exit__(self, *a):
        if self.session:
            try:
                self.session.__exit__(None, None, None)
            except Exception:
                pass

    def goto(self, url):
        self.session._page.goto(url, wait_until="domcontentloaded",
                                timeout=self.cfg.browser.timeout_s * 1000)

    def text(self):
        try:
            return self.session._page.inner_text("body") or ""
        except Exception:
            return ""

    def evaluate(self, js):
        return self.session._page.evaluate(js)

    def screenshot(self, path):
        try:
            self.session._page.screenshot(path=path, full_page=True)
        except Exception as e:
            print("     (screenshot camoufox fallito:", e, ")")


VARIANTS = {
    "cdp":       lambda cfg: CDPProbe(cfg, "cdp", spoof_gpu=False),
    "cdp-spoof": lambda cfg: CDPProbe(cfg, "cdp-spoof", spoof_gpu=True),
    "camoufox":  lambda cfg: CamoufoxProbe(cfg, "camoufox"),
}


def snapshot_pids(names):
    pids = set()
    for p in psutil.process_iter(["pid", "name"]):
        try:
            nm = (p.info["name"] or "").lower()
            if any(n in nm for n in names):
                pids.add(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return pids


def rss_mb(pids):
    seen, total, stack = set(), 0, list(pids)
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            p = psutil.Process(pid)
            total += p.memory_info().rss
            stack += [c.pid for c in p.children()]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return round(total / 1024 / 1024, 1)


def parse_deviceinfo(text):
    import re
    out = {}
    for k in DEVICEINFO_FLAGS:
        m = re.search(r'"%s"\s*:\s*(true|false)' % re.escape(k), text)
        if m:
            out[k] = (m.group(1) == "true")
    out["verdict"] = "human" if "You are human!" in text else ("bot" if "bot" in text.lower() else "?")
    return out


def parse_amiabot(text):
    """Estrae il verdetto di amiabot.app dal testo della pagina.

    Campi: classification (es. likely_human/likely_bot), risk (low/medium/high),
    score numerico, isBot derivato. `inconsistency_hits` = conteggio grezzo di
    token "mismatch"/"inconsistent" nel report: segnale di incoerenza del
    fingerprint (worker/request), indipendente dal behavior score. ATTENZIONE: il
    verdetto in cima mescola anche segnali comportamentali (mouse/eventi): in
    headless senza interazione puo' spostarsi verso "bot" anche per un browser
    legittimo -> per il confronto fingerprint guarda inconsistency_hits + la
    worker_coherence misurata da noi, non solo classification.
    """
    import re
    out = {}
    low = text.lower()
    m = re.search(r"classification[:\s]+([a-z_]+)", low)
    if m:
        out["classification"] = m.group(1)
    m = re.search(r"\brisk[:\s]+(low|medium|high|unknown)", low)
    if m:
        out["risk"] = m.group(1)
    m = re.search(r"(\d{1,3})\s*\n?\s*(LIKELY[_ ]?HUMAN|LIKELY[_ ]?BOT|HUMAN|BOT)", text)
    if m:
        out["score"] = int(m.group(1))
        out["label"] = m.group(2).replace(" ", "_").upper()
    cls = out.get("classification", "")
    if "bot" in cls:
        out["isBot"] = True
    elif "human" in cls:
        out["isBot"] = False
    elif out.get("label"):
        out["isBot"] = "BOT" in out["label"]
    out["inconsistency_hits"] = len(re.findall(r"mismatch|inconsistent", low))
    return out


def worker_coherence(main, worker):
    fields = ["ua", "platform", "hardwareConcurrency", "webglVendor", "webglRenderer"]
    per = {}
    consistent = True
    if not isinstance(worker, dict) or worker.get("error"):
        return {"worker_error": (worker or {}).get("error", "no worker result")}, False
    for f in fields:
        mv, wv = main.get(f), worker.get(f)
        same = (mv == wv)
        per[f] = {"main": mv, "worker": wv, "match": same}
        if not same:
            consistent = False
    return per, consistent


def run_once(factory, cfg, do_screenshot):
    probe = factory(cfg)
    label = probe.label
    res = {"backend": label}
    before = snapshot_pids(probe.browser_names)
    with probe:
        new_pids = snapshot_pids(probe.browser_names) - before
        res["launch_time_s"] = round(probe.launch_time_s, 2)
        res["os_used"] = cfg.camoufox.os if label == "camoufox" else "host"

        try:
            probe.goto(DEVICEINFO_URL)
            time.sleep(6)
            res["rss_mb"] = rss_mb(new_pids)

            main = probe.evaluate(MAIN_JS)
            res["main_signals"] = main
            probe.evaluate(WORKER_INJECT_JS)
            worker = None
            for _ in range(15):
                time.sleep(0.3)
                worker = probe.evaluate("window.__wr")
                if worker:
                    break
            res["worker_signals"] = worker
            per, ok = worker_coherence(main, worker or {})
            res["worker_coherence"] = {"consistent": ok, "fields": per}

            res.setdefault("suites", {})["deviceinfo"] = parse_deviceinfo(probe.text())
        except Exception as e:
            print("     ERRORE deviceinfo:", e)

        try:
            probe.goto(AMIABOT_URL)
            txt = ""
            for _ in range(15):
                time.sleep(1)
                txt = probe.text()
                if "classification" in txt.lower():
                    break
            res.setdefault("suites", {})["amiabot"] = parse_amiabot(txt)
        except Exception as e:
            print("     ERRORE amiabot:", e)

        for key, url in SCREENSHOT_SUITES:
            try:
                probe.goto(url)
                time.sleep(8)
                if do_screenshot:
                    probe.screenshot(str(OUTDIR / f"compare_{label}_{key}.png"))
            except Exception as e:
                print("     ERRORE %s: %s" % (key, e))
    return res


def _mm(vals):
    vals = [v for v in vals if isinstance(v, (int, float))]
    if not vals:
        return "-"
    m = statistics.mean(vals)
    if len(vals) == 1:
        return f"{m:.1f}"
    return f"{m:.1f} ({min(vals):.1f}-{max(vals):.1f})"


def _count_true(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return "-"
    return f"{sum(1 for v in vals if v is True)}/{len(vals)}"


def aggregate(runs):
    di = [r.get("suites", {}).get("deviceinfo", {}) for r in runs]
    ab = [r.get("suites", {}).get("amiabot", {}) for r in runs]
    ex = runs[0]
    return {
        "n": len(runs),
        "launch": _mm([r.get("launch_time_s") for r in runs]),
        "rss": _mm([r.get("rss_mb") for r in runs]),
        "os_used": ex.get("os_used", "-"),
        "worker_consistent": _count_true([r.get("worker_coherence", {}).get("consistent") for r in runs]),
        "isBot": _count_true([d.get("isBot") for d in di]),
        "hasInconsistentWorkerValues": _count_true([d.get("hasInconsistentWorkerValues") for d in di]),
        "isWebGLInconsistent": _count_true([d.get("isWebGLInconsistent") for d in di]),
        "isAutomatedWithCDP": _count_true([d.get("isAutomatedWithCDP") for d in di]),
        "amiabot_isBot": _count_true([a.get("isBot") for a in ab]),
        "amiabot_score": _mm([a.get("score") for a in ab]),
        "amiabot_inconsistency": _mm([a.get("inconsistency_hits") for a in ab]),
        "amiabot_class": ex.get("suites", {}).get("amiabot", {}).get("classification", "-"),
        "gpu_main": (ex.get("main_signals") or {}).get("webglRenderer"),
        "gpu_worker": (ex.get("worker_signals") or {}).get("webglRenderer"),
        "cores": (ex.get("main_signals") or {}).get("hardwareConcurrency"),
    }


def print_table(aggr_by_label):
    labels = list(aggr_by_label.keys())
    rows = [
        ("Metrica", *labels),
        ("run (n)", *[aggr_by_label[l]["n"] for l in labels]),
        ("launch time s (media,range)", *[aggr_by_label[l]["launch"] for l in labels]),
        ("RSS MB (media,range)", *[aggr_by_label[l]["rss"] for l in labels]),
        ("OS presentato", *[aggr_by_label[l]["os_used"] for l in labels]),
        ("worker coerente", *[aggr_by_label[l]["worker_consistent"] for l in labels]),
        ("deviceinfo isBot=true", *[aggr_by_label[l]["isBot"] for l in labels]),
        ("hasInconsistentWorkerValues=true", *[aggr_by_label[l]["hasInconsistentWorkerValues"] for l in labels]),
        ("isWebGLInconsistent=true", *[aggr_by_label[l]["isWebGLInconsistent"] for l in labels]),
        ("isAutomatedWithCDP=true", *[aggr_by_label[l]["isAutomatedWithCDP"] for l in labels]),
        ("amiabot isBot=true", *[aggr_by_label[l]["amiabot_isBot"] for l in labels]),
        ("amiabot class (esempio)", *[aggr_by_label[l]["amiabot_class"] for l in labels]),
        ("amiabot score (media,range)", *[aggr_by_label[l]["amiabot_score"] for l in labels]),
        ("amiabot incoerenze (media,range)", *[aggr_by_label[l]["amiabot_inconsistency"] for l in labels]),
        ("cores (esempio)", *[aggr_by_label[l]["cores"] for l in labels]),
    ]
    w = 34
    cw = 26
    print("\n" + "=" * (w + cw * len(labels)))
    print("TABELLA COMPARATIVA (aggregata)")
    print("=" * (w + cw * len(labels)))
    for row in rows:
        print(str(row[0]).ljust(w) + "".join(str(c).ljust(cw) for c in row[1:]))
    print("\nGPU main vs worker (1a run) - il mismatch = incoerenza spoofing:")
    for l in labels:
        print(f"  [{l}] main   : {aggr_by_label[l]['gpu_main']}")
        print(f"  [{l}] worker : {aggr_by_label[l]['gpu_worker']}")
    print("\nScreenshot + JSON completo in:", OUTDIR)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="all",
                    help="all | csv di: cdp,cdp-spoof,camoufox")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--camoufox-os", default=None,
                    help="override camoufox.os (windows|macos|linux|random)")
    ap.add_argument("--headless", dest="headless", action="store_true", default=None)
    ap.add_argument("--headed", dest="headless", action="store_false")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.headless is not None:
        cfg.browser.headless = args.headless
    if args.camoufox_os:
        cfg.camoufox.os = args.camoufox_os

    if args.backend == "all":
        selected = ["cdp", "cdp-spoof", "camoufox"]
    else:
        selected = [s.strip() for s in args.backend.split(",") if s.strip()]
    bad = [s for s in selected if s not in VARIANTS]
    if bad:
        raise SystemExit("Varianti sconosciute: %s (valide: %s)" % (bad, list(VARIANTS)))

    print("headless:", cfg.browser.headless, "| camoufox os:", cfg.camoufox.os,
          "| varianti:", selected, "| repeat:", args.repeat)

    all_runs = {}
    for label in selected:
        all_runs[label] = []
        for i in range(args.repeat):
            print(f"### {label}  run {i+1}/{args.repeat}")
            try:
                r = run_once(VARIANTS[label], cfg, do_screenshot=(i == 0))
                print("   launch %.2fs  RSS %s MB  worker_consistent=%s  isBot=%s" % (
                    r.get("launch_time_s", -1), r.get("rss_mb", "-"),
                    r.get("worker_coherence", {}).get("consistent"),
                    r.get("suites", {}).get("deviceinfo", {}).get("isBot"),
                ))
                all_runs[label].append(r)
            except Exception as e:
                print("   !!! run fallita:", e)

    (OUTDIR / "compare_result.json").write_text(
        json.dumps(all_runs, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    aggr = {l: aggregate(runs) for l, runs in all_runs.items() if runs}
    if aggr:
        print_table(aggr)
    print("\nJSON completo:", OUTDIR / "compare_result.json")


if __name__ == "__main__":
    main()
