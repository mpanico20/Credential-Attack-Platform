"""Native desktop GUI (Tkinter) for the engine.

Three jobs, in a single native window with no local server and no browser:

* **Crea Config** - raw YAML editor with live validation (config_schema).
* **Esegui**      - compose and launch attack runs as non-blocking subprocesses
                    (runner), with a live console tail and stop/remove.
* **Analisi Run** - metrics and charts over the JSONL logs (metrics).

This module only provides a Tk front-end over dashboard.runner / config_schema /
metrics; the engine itself is launched as a subprocess (python main.py attack ...
in whatever venv the user points at). Charts use matplotlib when available and
fall back to a plain table otherwise, so the GUI adds no hard dependency.

Launch:  pythonw dashboard/gui.py   (or:  python -m dashboard.gui)
"""
from __future__ import annotations

import sys
from pathlib import Path

_here = Path(__file__).resolve()
ROOT = next((p for p in _here.parents if (p / "main.py").exists()), _here.parent.parent)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from dashboard import config_schema as schema
from dashboard import runner
from dashboard.webapp_common import CONFIGS_DIR

try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    HAS_MPL = True
except Exception:
    HAS_MPL = False

POLL_MS = 1500

STATUS_TEXT = {
    "running": "running - in corso",
    "done": "done - completata",
    "failed": "failed - fallita",
}


def data_files() -> list[str]:
    """Candidate input files under data/, as paths relative to the engine root."""
    data_dir = ROOT / "data"
    if not data_dir.exists():
        return []
    out = []
    for p in sorted(data_dir.rglob("*")):
        if p.is_file() and p.suffix.lower() in (".txt", ".csv", ".lst"):
            out.append(str(p.relative_to(ROOT)).replace("\\", "/"))
    return out


def _as_root_relative(path: str) -> str:
    """Return path relative to ROOT when it sits under it, else the path as-is."""
    try:
        return str(Path(path).resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return path


class FilePicker(ttk.Frame):
    """A combobox over data/ plus a Sfoglia... button. `.get()` returns a path
    (relative to the engine root when possible) or None."""

    def __init__(self, master, label: str):
        super().__init__(master)
        ttk.Label(self, text=label, width=22).grid(row=0, column=0, sticky="w")
        self.var = tk.StringVar()
        self.combo = ttk.Combobox(self, textvariable=self.var, width=46,
                                  values=data_files())
        self.combo.grid(row=0, column=1, sticky="we", padx=4)
        ttk.Button(self, text="Sfoglia...", command=self._browse).grid(row=0, column=2)
        self.columnconfigure(1, weight=1)

    def _browse(self) -> None:
        chosen = filedialog.askopenfilename(initialdir=str(ROOT / "data"))
        if chosen:
            self.var.set(_as_root_relative(chosen))

    def refresh(self) -> None:
        self.combo["values"] = data_files()

    def get(self) -> str | None:
        val = self.var.get().strip()
        return val or None


class ConfigTab(ttk.Frame):
    def __init__(self, master, app: "App"):
        super().__init__(master, padding=8)
        self.app = app

        left = ttk.Frame(self)
        left.pack(side="left", fill="y", padx=(0, 8))
        ttk.Label(left, text="Config in configs/").pack(anchor="w")
        self.listbox = tk.Listbox(left, width=26, height=18, exportselection=False)
        self.listbox.pack(fill="y", expand=True)
        self.listbox.bind("<Double-Button-1>", lambda _e: self.open_selected())

        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Apri", command=self.open_selected).pack(side="left")
        ttk.Button(btns, text="Nuova", command=self.new_default).pack(side="left", padx=4)
        ttk.Button(btns, text="Elimina", command=self.delete_selected).pack(side="left")

        right = ttk.Frame(self)
        right.pack(side="left", fill="both", expand=True)

        name_row = ttk.Frame(right)
        name_row.pack(fill="x")
        ttk.Label(name_row, text="Nome file").pack(side="left")
        self.name_var = tk.StringVar(value="config_custom.yaml")
        ttk.Entry(name_row, textvariable=self.name_var, width=32).pack(side="left", padx=6)
        ttk.Button(name_row, text="Valida", command=self.validate).pack(side="left")
        ttk.Button(name_row, text="Salva in configs/",
                   command=self.save).pack(side="left", padx=6)

        self.editor = tk.Text(right, wrap="none", undo=True, height=22,
                              font=("Consolas", 10))
        self.editor.pack(fill="both", expand=True, pady=6)
        yscroll = ttk.Scrollbar(self.editor, command=self.editor.yview)
        yscroll.pack(side="right", fill="y")
        self.editor.configure(yscrollcommand=yscroll.set)

        self.status = tk.Text(right, height=6, wrap="word", state="disabled",
                             background="#f4f4f4", font=("Consolas", 9))
        self.status.pack(fill="x")

        self.refresh_list()
        self._set_editor(schema.default_config_text())
        self.name_var.set("config_custom.yaml")
        self._show_status("Template di default. Premi 'Nuova' per creare il file, "
                          "oppure modifica e 'Salva'.")

    def refresh_list(self) -> None:
        self.listbox.delete(0, tk.END)
        for name in schema.list_configs():
            self.listbox.insert(tk.END, name)

    def _selected_name(self) -> str | None:
        sel = self.listbox.curselection()
        return self.listbox.get(sel[0]) if sel else None

    def _set_editor(self, text: str) -> None:
        self.editor.delete("1.0", tk.END)
        self.editor.insert("1.0", text)

    def _free_default_name(self) -> str:
        """Un nome config_custom*.yaml non ancora presente in configs/."""
        existing = set(schema.list_configs())
        if "config_custom.yaml" not in existing:
            return "config_custom.yaml"
        i = 1
        while f"config_custom_{i}.yaml" in existing:
            i += 1
        return f"config_custom_{i}.yaml"

    def _select_in_list(self, name: str) -> None:
        for i in range(self.listbox.size()):
            if self.listbox.get(i) == name:
                self.listbox.selection_clear(0, tk.END)
                self.listbox.selection_set(i)
                self.listbox.see(i)
                break

    def new_default(self) -> None:
        """Crea subito un file con i valori standard in configs/ e lo apre."""
        text = schema.default_config_text()
        name = self._free_default_name()
        path = schema.save_config_text(name, text)
        self._set_editor(text)
        self.name_var.set(path.name)
        self.refresh_list()
        self._select_in_list(path.name)
        self._show_status(f"Creata configs/{path.name} con valori standard. "
                          "Modifica e premi Salva per aggiornarla.")
        self.app.on_configs_changed()

    def open_selected(self) -> None:
        name = self._selected_name()
        if not name:
            return
        self._set_editor(schema.load_config_text(name))
        self.name_var.set(name)
        self.validate()

    def delete_selected(self) -> None:
        name = self._selected_name()
        if not name:
            return
        if messagebox.askyesno("Elimina config", f"Eliminare configs/{name}?"):
            schema.delete_config_file(name)
            self.refresh_list()

    def validate(self) -> bool:
        text = self.editor.get("1.0", "end-1c")
        ok, _data, messages = schema.validate_yaml_text(text)
        if ok:
            self._show_status("Config valida.")
        else:
            self._show_status("Problemi da sistemare:\n- " + "\n- ".join(messages))
        return ok

    def save(self) -> None:
        if not self.validate():
            if not messagebox.askyesno("Salva comunque",
                                       "La config ha problemi. Salvare lo stesso?"):
                return
        text = self.editor.get("1.0", "end-1c")
        path = schema.save_config_text(self.name_var.get(), text)
        self.name_var.set(path.name)
        self.refresh_list()
        self._show_status(f"Salvata configs/{path.name}")
        self.app.on_configs_changed()

    def _show_status(self, msg: str) -> None:
        self.status.configure(state="normal")
        self.status.delete("1.0", tk.END)
        self.status.insert("1.0", msg)
        self.status.configure(state="disabled")


class EseguiTab(ttk.Frame):
    CFG = "(da config)"

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=8)
        self.app = app

        form = ttk.LabelFrame(self, text="Parametri run", padding=8)
        form.pack(fill="x")

        row1 = ttk.Frame(form)
        row1.pack(fill="x", pady=2)
        ttk.Label(row1, text="Config", width=12).pack(side="left")
        self.cfg_var = tk.StringVar()
        self.cfg_combo = ttk.Combobox(row1, textvariable=self.cfg_var, width=28,
                                     state="readonly")
        self.cfg_combo.pack(side="left")
        self.cfg_combo.bind("<<ComboboxSelected>>", lambda _e: self._reload_targets())

        ttk.Label(row1, text="Target", width=10).pack(side="left", padx=(12, 0))
        self.target_var = tk.StringVar()
        self.target_combo = ttk.Combobox(row1, textvariable=self.target_var, width=24,
                                        state="readonly")
        self.target_combo.pack(side="left")

        ttk.Label(row1, text="Attack", width=8).pack(side="left", padx=(12, 0))
        self.attack_var = tk.StringVar(value=runner.ATTACK_TYPES[0])
        attack_combo = ttk.Combobox(row1, textvariable=self.attack_var, width=14,
                                   state="readonly", values=runner.ATTACK_TYPES)
        attack_combo.pack(side="left")
        attack_combo.bind("<<ComboboxSelected>>", lambda _e: self._rebuild_inputs())

        row2 = ttk.Frame(form)
        row2.pack(fill="x", pady=2)
        ttk.Label(row2, text="Defense label", width=12).pack(side="left")
        self.defense_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.defense_var, width=24).pack(side="left")
        ttk.Label(row2, text="Evasion label", width=14).pack(side="left", padx=(12, 0))
        self.evasion_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.evasion_var, width=24).pack(side="left")

        self.inputs_frame = ttk.Frame(form)
        self.inputs_frame.pack(fill="x", pady=4)
        self.username_var = tk.StringVar()
        self._pickers: dict[str, FilePicker] = {}

        row3 = ttk.Frame(form)
        row3.pack(fill="x", pady=2)
        self.mutation_var = tk.BooleanVar(value=False)
        self.mutation_chk = ttk.Checkbutton(row3, text="Mutation engine (--mutation)",
                                           variable=self.mutation_var)
        self.mutation_chk.pack(side="left")
        self.proxy_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row3, text="Usa proxy (--use-proxy)",
                        variable=self.proxy_var).pack(side="left", padx=12)

        capf = ttk.LabelFrame(form, text="CAPTCHA (override config; solo cdp/camoufox)", padding=6)
        capf.pack(fill="x", pady=4)
        ttk.Label(capf, text="Tipo", width=6).pack(side="left")
        self.captcha_type_var = tk.StringVar(value=self.CFG)
        ttk.Combobox(capf, textvariable=self.captcha_type_var, width=14, state="readonly",
                     values=[self.CFG, "auto", "turnstile", "recaptcha_v2", "recaptcha_v3"]
                     ).pack(side="left")
        ttk.Label(capf, text="Solver", width=8).pack(side="left", padx=(10, 0))
        self.captcha_solver_var = tk.StringVar(value=self.CFG)
        ttk.Combobox(capf, textvariable=self.captcha_solver_var, width=12, state="readonly",
                     values=[self.CFG, "none", "capsolver"]).pack(side="left")
        ttk.Label(capf, text="Key", width=5).pack(side="left", padx=(10, 0))
        self.captcha_key_var = tk.StringVar()
        ttk.Entry(capf, textvariable=self.captcha_key_var, width=24, show="*").pack(side="left")

        expf = ttk.LabelFrame(form, text="Exploit - Cella A (post-credenziale, SOLO lab/LAN)", padding=6)
        expf.pack(fill="x", pady=4)
        exrow1 = ttk.Frame(expf)
        exrow1.pack(fill="x")
        self.exploit_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(exrow1, text="Attiva (--exploit-on-success)",
                        variable=self.exploit_var).pack(side="left")
        ttk.Label(exrow1, text="LHOST", width=7).pack(side="left", padx=(10, 0))
        self.exploit_lhost_var = tk.StringVar()
        ttk.Entry(exrow1, textvariable=self.exploit_lhost_var, width=16).pack(side="left")
        ttk.Label(exrow1, text="LPORT", width=7).pack(side="left", padx=(10, 0))
        self.exploit_lport_var = tk.StringVar(value="4444")
        ttk.Entry(exrow1, textvariable=self.exploit_lport_var, width=8).pack(side="left")
        exrow2 = ttk.Frame(expf)
        exrow2.pack(fill="x", pady=(4, 0))
        ttk.Label(exrow2, text="Base URL", width=9).pack(side="left")
        self.exploit_base_url_var = tk.StringVar()
        ttk.Entry(exrow2, textvariable=self.exploit_base_url_var, width=34).pack(side="left")
        ttk.Label(exrow2, text="Payload", width=9).pack(side="left", padx=(10, 0))
        self.exploit_payload_var = tk.StringVar()
        ttk.Entry(exrow2, textvariable=self.exploit_payload_var, width=20).pack(side="left")

        row4 = ttk.Frame(form)
        row4.pack(fill="x", pady=2)
        ttk.Label(row4, text="Python subprocess", width=16).pack(side="left")
        self.python_var = tk.StringVar(value=sys.executable)
        ttk.Entry(row4, textvariable=self.python_var, width=60).pack(side="left", padx=4)

        launch_row = ttk.Frame(form)
        launch_row.pack(fill="x", pady=6)
        ttk.Button(launch_row, text="Lancia run", command=self.launch).pack(side="left")
        ttk.Button(launch_row, text="Anteprima comando",
                   command=self.preview_command).pack(side="left", padx=6)

        ttk.Label(form, text="Comando:").pack(anchor="w")
        self.cmd_text = tk.Text(form, height=3, wrap="word", state="disabled",
                                background="#f4f4f4", font=("Consolas", 9))
        self.cmd_text.pack(fill="x")

        panel = ttk.LabelFrame(self, text="Run di questa sessione", padding=8)
        panel.pack(fill="both", expand=True, pady=(8, 0))

        top = ttk.Frame(panel)
        top.pack(fill="x")
        self.counts = ttk.Label(top, text="Totali: 0   In corso: 0")
        self.counts.pack(side="left")
        ttk.Button(top, text="Stop", command=self.stop_selected).pack(side="right")
        ttk.Button(top, text="Rimuovi", command=self.remove_selected).pack(side="right", padx=4)

        cols = ("status", "run_id", "started")
        self.tree = ttk.Treeview(panel, columns=cols, show="headings", height=6)
        for c, w in (("status", 150), ("run_id", 340), ("started", 160)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="x", pady=4)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_console())

        self.console = tk.Text(panel, height=12, wrap="none", state="disabled",
                             background="#1e1e1e", foreground="#d4d4d4",
                             font=("Consolas", 9))
        self.console.pack(fill="both", expand=True)

        self.refresh_configs()
        self._rebuild_inputs()
        self.after(POLL_MS, self._poll)

    def refresh_configs(self) -> None:
        cfgs = schema.list_configs()
        self.cfg_combo["values"] = cfgs
        if cfgs and self.cfg_var.get() not in cfgs:
            self.cfg_var.set(cfgs[0])
        self._reload_targets()

    def _reload_targets(self) -> None:
        name = self.cfg_var.get()
        targets: list[str] = []
        if name:
            try:
                targets = schema.target_names(schema.load_config_file(name))
            except Exception:
                targets = []
        self.target_combo["values"] = targets
        self.target_var.set(targets[0] if targets else "")

    def _rebuild_inputs(self) -> None:
        for child in self.inputs_frame.winfo_children():
            child.destroy()
        self._pickers.clear()
        attack = self.attack_var.get()

        if attack == "stuffing":
            self._add_picker("combo", "Combo list (user:pass)")
            self.mutation_var.set(False)
            self.mutation_chk.state(["disabled"])
        else:
            self.mutation_chk.state(["!disabled"])
            if attack == "spray":
                self._add_picker("usernames", "Usernames")
                self._add_picker("passwords", "Passwords")
            elif attack == "bruteforce":
                urow = ttk.Frame(self.inputs_frame)
                urow.pack(fill="x", pady=2)
                ttk.Label(urow, text="Username singolo", width=22).pack(side="left")
                ttk.Entry(urow, textvariable=self.username_var, width=30).pack(side="left", padx=4)
                self._add_picker("passwords", "Passwords")

    def _add_picker(self, key: str, label: str) -> None:
        picker = FilePicker(self.inputs_frame, label)
        picker.pack(fill="x", pady=2)
        self._pickers[key] = picker

    def _compose_spec(self) -> runner.RunSpec:
        """Legge il form nei parametri di una RunSpec (condiviso da launch/anteprima)."""
        attack = self.attack_var.get()
        exploit_on = self.exploit_var.get()
        cap_type = self.captcha_type_var.get()
        cap_solver = self.captcha_solver_var.get()
        lport_raw = self.exploit_lport_var.get().strip()
        return runner.RunSpec(
            config_path=CONFIGS_DIR / self.cfg_var.get(),
            target=self.target_var.get(),
            attack_type=attack,
            combo_list=self._pickers["combo"].get() if "combo" in self._pickers else None,
            usernames=self._pickers["usernames"].get() if "usernames" in self._pickers else None,
            passwords=self._pickers["passwords"].get() if "passwords" in self._pickers else None,
            username=self.username_var.get().strip() or None if attack == "bruteforce" else None,
            mutation=self.mutation_var.get(),
            use_proxy=self.proxy_var.get(),
            defense_config=self.defense_var.get().strip() or None,
            evasion_config=self.evasion_var.get().strip() or None,
            captcha_type=None if cap_type == self.CFG else cap_type,
            captcha_solver=None if cap_solver == self.CFG else cap_solver,
            captcha_key=self.captcha_key_var.get().strip() or None,
            exploit_on_success=exploit_on,
            exploit_base_url=self.exploit_base_url_var.get().strip() or None,
            exploit_lhost=self.exploit_lhost_var.get().strip() or None,
            exploit_lport=int(lport_raw) if (exploit_on and lport_raw.isdigit()) else None,
            exploit_payload=self.exploit_payload_var.get().strip() or None,
        )

    def _set_cmd(self, text: str) -> None:
        self.cmd_text.configure(state="normal")
        self.cmd_text.delete("1.0", tk.END)
        self.cmd_text.insert("1.0", text)
        self.cmd_text.configure(state="disabled")

    def preview_command(self) -> None:
        """Mostra la riga di comando senza lanciare nulla (per test)."""
        if not self.cfg_var.get() or not self.target_var.get():
            messagebox.showerror("Anteprima", "Seleziona config e target.")
            return
        try:
            argv = self._compose_spec().build_argv(python=self.python_var.get().strip() or None)
        except runner.RunSpecError as exc:
            self._set_cmd(f"(parametri incompleti) {exc}")
            return
        self._set_cmd(" ".join(argv))

    def launch(self) -> None:
        if not self.cfg_var.get() or not self.target_var.get():
            messagebox.showerror("Run", "Seleziona config e target.")
            return
        try:
            handle = runner.launch(self._compose_spec(),
                                   python=self.python_var.get().strip() or None)
        except runner.RunSpecError as exc:
            messagebox.showerror("Parametri run", str(exc))
            return
        self._set_cmd(" ".join(handle.argv))
        self._refresh_runs()
        messagebox.showinfo("Run avviata", f"Avviata run {handle.run_id}")

    def _selected_run_id(self) -> str | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return self.tree.item(sel[0], "values")[1]

    def stop_selected(self) -> None:
        rid = self._selected_run_id()
        handle = runner.get(rid) if rid else None
        if handle:
            handle.stop()

    def remove_selected(self) -> None:
        rid = self._selected_run_id()
        if rid:
            runner.remove(rid)
            self._refresh_runs()

    def _refresh_runs(self) -> None:
        runs = runner.all_runs()
        keep = self._selected_run_id()
        self.tree.delete(*self.tree.get_children())
        for h in runs:
            self.tree.insert("", tk.END, iid=h.run_id, values=(
                STATUS_TEXT.get(h.status, h.status),
                h.run_id,
                h.started_at.strftime("%H:%M:%S"),
            ))
        if keep and self.tree.exists(keep):
            self.tree.selection_set(keep)
        running = sum(1 for h in runs if h.status == "running")
        self.counts.configure(text=f"Totali: {len(runs)}   In corso: {running}")

    def _show_console(self) -> None:
        rid = self._selected_run_id()
        handle = runner.get(rid) if rid else None
        text = handle.read_console() if handle else ""
        self.console.configure(state="normal")
        self.console.delete("1.0", tk.END)
        self.console.insert("1.0", text or "(nessun output ancora)")
        self.console.see(tk.END)
        self.console.configure(state="disabled")

    def _poll(self) -> None:
        self._refresh_runs()
        if self._selected_run_id():
            self._show_console()
        self.after(POLL_MS, self._poll)


class AnalisiTab(ttk.Frame):
    def __init__(self, master, app: "App"):
        super().__init__(master, padding=8)
        self.app = app

        from attack_logging.attack_logger import list_runs, load_run
        from config import load_config
        from dashboard import metrics
        self._list_runs = list_runs
        self._load_run = load_run
        self._metrics = metrics

        cfg_path = ROOT / "config.yaml"
        try:
            self.output_dir = ROOT / load_config(cfg_path).logging.output_dir
        except Exception:
            self.output_dir = ROOT / "logs"

        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="Run").pack(side="left")
        self.run_var = tk.StringVar()
        self.run_combo = ttk.Combobox(top, textvariable=self.run_var, width=48,
                                     state="readonly")
        self.run_combo.pack(side="left", padx=6)
        self.run_combo.bind("<<ComboboxSelected>>", lambda _e: self.load_selected())
        ttk.Button(top, text="Aggiorna", command=self.refresh_runs).pack(side="left")

        self.metrics_lbl = ttk.Label(self, text="", font=("Consolas", 10))
        self.metrics_lbl.pack(anchor="w", pady=6)

        self.chart_frame = ttk.Frame(self)
        self.chart_frame.pack(fill="both", expand=False)

        tbl_frame = ttk.LabelFrame(self, text="Raw attempts (max 500)", padding=4)
        tbl_frame.pack(fill="both", expand=True, pady=(6, 0))
        self.table = ttk.Treeview(tbl_frame, show="headings", height=8)
        xs = ttk.Scrollbar(tbl_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(xscrollcommand=xs.set)
        self.table.pack(side="top", fill="both", expand=True)
        xs.pack(side="bottom", fill="x")

        self._runs_map: dict[str, Path] = {}
        self.refresh_runs()

    def refresh_runs(self) -> None:
        runs = self._list_runs(self.output_dir)
        self._runs_map = {p.stem: p for p in runs}
        self.run_combo["values"] = list(self._runs_map.keys())
        if self._runs_map:
            if self.run_var.get() not in self._runs_map:
                self.run_var.set(next(iter(self._runs_map)))
            self.load_selected()
        else:
            self.metrics_lbl.configure(
                text=f"Nessuna run in {self.output_dir}. Lancia un attacco prima.")

    def load_selected(self) -> None:
        path = self._runs_map.get(self.run_var.get())
        if not path:
            return
        attempts = self._load_run(path)
        df = self._metrics.to_dataframe(attempts)

        lat = self._metrics.latency_stats(df)
        avg = f"{lat['mean_ms']:.0f} ms" if lat["mean_ms"] else "-"
        text = (
            f"Attempts: {len(df)}    "
            f"Success: {self._metrics.success_rate(df):.1%}    "
            f"Block: {self._metrics.block_rate(df):.1%}    "
            f"Avg latency: {avg}"
        )
        cap = self._metrics.captcha_breakdown(df)
        if cap:
            bypass = f"{cap['bypass_rate']:.0%}" if cap["bypass_rate"] is not None else "-"
            text += (
                f"\nCAPTCHA  present: {cap['present']}    bypass: {bypass}    "
                f"solved/auto: {cap['solved']}/{cap['auto_passed']}    "
                f"blocked: {cap['blocked']}"
            )
        self.metrics_lbl.configure(text=text)

        self._draw_charts(df)
        self._fill_table(df)

    def _draw_charts(self, df) -> None:
        for child in self.chart_frame.winfo_children():
            child.destroy()
        if df.empty:
            return
        breakdown = self._metrics.outcome_breakdown(df)
        timeline = self._metrics.attempts_over_time(df)

        if HAS_MPL:
            fig = Figure(figsize=(9, 2.8), dpi=100)
            ax1 = fig.add_subplot(1, 2, 1)
            ax1.bar(breakdown["outcome"], breakdown["count"])
            ax1.set_title("Outcome breakdown")
            ax1.tick_params(axis="x", rotation=30)
            ax2 = fig.add_subplot(1, 2, 2)
            if not timeline.empty:
                ax2.plot(timeline["timestamp"], timeline["attempts"], marker="o")
            ax2.set_title("Attempts over time")
            fig.tight_layout()
            canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="x")
        else:
            txt = "  ".join(f"{r.outcome}={r.count}" for r in breakdown.itertuples())
            ttk.Label(self.chart_frame,
                      text="Outcome: " + txt + "   (installa matplotlib per i grafici)",
                      font=("Consolas", 10)).pack(anchor="w")

    def _fill_table(self, df) -> None:
        self.table.delete(*self.table.get_children())
        if df.empty:
            self.table["columns"] = ()
            return
        cols = list(df.columns)
        self.table["columns"] = cols
        for c in cols:
            self.table.heading(c, text=c)
            self.table.column(c, width=120, anchor="w", stretch=False)
        for _idx, row in df.head(500).iterrows():
            self.table.insert("", tk.END, values=[str(v) for v in row.tolist()])


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Credential Attack Platform")
        self.geometry("1100x760")

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.config_tab = ConfigTab(notebook, self)
        self.esegui_tab = EseguiTab(notebook, self)
        self.analisi_tab = AnalisiTab(notebook, self)
        notebook.add(self.config_tab, text="Crea Config")
        notebook.add(self.esegui_tab, text="Esegui")
        notebook.add(self.analisi_tab, text="Analisi Run")

    def on_configs_changed(self) -> None:
        """Called when the config list changes, so the Esegui tab stays in sync."""
        self.esegui_tab.refresh_configs()


def main() -> None:
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    App().mainloop()


if __name__ == "__main__":
    main()
