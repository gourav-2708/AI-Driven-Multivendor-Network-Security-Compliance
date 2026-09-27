# -*- coding: utf-8 -*-
"""
gui.py  -  net-audit Desktop GUI (tkinter)
Native Python desktop app wrapping net-audit.exe
Run:  python desktop/gui.py
"""

import json
import os
import subprocess
import sys
import threading
import tkinter as tk
import tkinter.filedialog as fd
import tkinter.font as tkfont
from pathlib import Path
from tkinter import ttk

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).parent
ROOT_DIR    = BASE_DIR.parent
BINARY_NAME = "net-audit.exe" if sys.platform == "win32" else "net-audit"
BINARY      = ROOT_DIR / BINARY_NAME

# ---------------------------------------------------------------------------
# Colour palette  (dark theme)
# ---------------------------------------------------------------------------
BG       = "#0f1117"
SURFACE  = "#1a1f2e"
SURFACE2 = "#22263a"
BORDER   = "#2e3450"
ACCENT   = "#4f8ef7"
TEXT     = "#e2e8f0"
MUTED    = "#8892a4"
GOOD     = "#22c55e"
WARN     = "#eab308"
CRIT     = "#ef4444"
HIGH_C   = "#f97316"
MED_C    = "#eab308"
LOW_C    = "#64748b"

SEV_COLOR = {
    "CRITICAL": CRIT,
    "HIGH":     HIGH_C,
    "MEDIUM":   MED_C,
    "LOW":      LOW_C,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def score_color(s):
    if s >= 80: return GOOD
    if s >= 50: return WARN
    return CRIT


def run_audit(file_paths, vendor="auto", severity="low"):
    """Call net-audit.exe, return parsed dict or {"error": "..."}."""
    if not BINARY.exists():
        return {"error": f"Binary not found: {BINARY}"}
    cmd = [str(BINARY), "--format", "json", "--severity", severity, "--no-color"]
    if vendor != "auto":
        cmd += ["--vendor", vendor]
    cmd += [str(p) for p in file_paths]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                           cwd=str(ROOT_DIR))
        raw = r.stdout.strip()
        if not raw:
            lines = [l for l in r.stderr.splitlines()
                     if l.strip() and not l.startswith("[INF]") and not l.startswith("[WRN]")]
            msg = lines[-1].strip() if lines else "No output from auditor"
            if "no files were successfully audited" in msg.lower():
                msg = "No supported config found. Use .cfg / .conf / .txt files."
            return {"error": msg}
        return json.loads(raw)
    except subprocess.TimeoutExpired:
        return {"error": "Audit timed out (>60 s)"}
    except json.JSONDecodeError as e:
        return {"error": f"Bad JSON: {e}"}


# ---------------------------------------------------------------------------
# Main Application Window
# ---------------------------------------------------------------------------
class NetAuditApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("net-audit  -  Network Security Compliance Auditor")
        self.geometry("1050x720")
        self.minsize(800, 580)
        self.configure(bg=BG)

        # Fonts
        self._setup_fonts()

        # State
        self.selected_files = []
        self.report_data    = None

        # Build UI
        self._build_header()
        self._build_main()
        self._build_status_bar()

    # ------------------------------------------------------------------
    def _setup_fonts(self):
        self.f_title  = tkfont.Font(family="Segoe UI", size=13, weight="bold")
        self.f_head   = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self.f_body   = tkfont.Font(family="Segoe UI", size=9)
        self.f_mono   = tkfont.Font(family="Consolas", size=9)
        self.f_score  = tkfont.Font(family="Segoe UI", size=36, weight="bold")
        self.f_label  = tkfont.Font(family="Segoe UI", size=8)

    # ------------------------------------------------------------------
    def _build_header(self):
        hdr = tk.Frame(self, bg=SURFACE, pady=10)
        hdr.pack(fill="x", side="top")

        tk.Label(hdr, text="net-audit", font=self.f_title,
                 fg=ACCENT, bg=SURFACE).pack(side="left", padx=16)
        tk.Label(hdr, text="Multi-Vendor Network Security Compliance Auditor",
                 font=self.f_body, fg=MUTED, bg=SURFACE).pack(side="left")

        # Binary status pill
        status_text = "Binary: FOUND" if BINARY.exists() else "Binary: NOT FOUND"
        status_fg   = GOOD if BINARY.exists() else CRIT
        tk.Label(hdr, text=status_text, font=self.f_label,
                 fg=status_fg, bg=SURFACE).pack(side="right", padx=16)

    # ------------------------------------------------------------------
    def _build_main(self):
        pane = tk.PanedWindow(self, orient="horizontal", bg=BG,
                              sashwidth=4, sashrelief="flat")
        pane.pack(fill="both", expand=True, padx=8, pady=8)

        pane.add(self._build_left_panel(pane),  minsize=280)
        pane.add(self._build_right_panel(pane), minsize=460)

    # ------------------------------------------------------------------
    def _build_left_panel(self, parent):
        frame = tk.Frame(parent, bg=SURFACE, padx=12, pady=12)

        # --- File selection ---
        tk.Label(frame, text="CONFIG FILES", font=self.f_head,
                 fg=ACCENT, bg=SURFACE).pack(anchor="w")

        self.file_listbox = tk.Listbox(
            frame, bg=SURFACE2, fg=TEXT, selectbackground=ACCENT,
            selectforeground=BG, font=self.f_mono, height=8,
            borderwidth=0, highlightthickness=1, highlightcolor=BORDER,
            activestyle="none"
        )
        self.file_listbox.pack(fill="x", pady=(6, 4))

        btn_row = tk.Frame(frame, bg=SURFACE)
        btn_row.pack(fill="x", pady=(0, 10))

        self._btn(btn_row, "Add Files", self._add_files).pack(side="left", padx=(0, 4))
        self._btn(btn_row, "Clear",     self._clear_files, danger=True).pack(side="left")

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=8)

        # --- Options ---
        tk.Label(frame, text="OPTIONS", font=self.f_head,
                 fg=ACCENT, bg=SURFACE).pack(anchor="w")

        # Vendor
        tk.Label(frame, text="Vendor:", font=self.f_body,
                 fg=TEXT, bg=SURFACE).pack(anchor="w", pady=(6, 0))
        self.vendor_var = tk.StringVar(value="auto")
        vendor_cb = ttk.Combobox(frame, textvariable=self.vendor_var,
                                 values=["auto", "cisco", "juniper", "fortinet"],
                                 state="readonly", font=self.f_body)
        vendor_cb.pack(fill="x", pady=(2, 8))

        # Minimum severity
        tk.Label(frame, text="Min. Severity:", font=self.f_body,
                 fg=TEXT, bg=SURFACE).pack(anchor="w")
        self.severity_var = tk.StringVar(value="low")
        sev_cb = ttk.Combobox(frame, textvariable=self.severity_var,
                               values=["low", "medium", "high", "critical"],
                               state="readonly", font=self.f_body)
        sev_cb.pack(fill="x", pady=(2, 16))

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=4)

        # --- Run button ---
        self.run_btn = tk.Button(
            frame, text="RUN AUDIT",
            font=self.f_head, fg="white", bg=ACCENT,
            activebackground="#3a7ae8", activeforeground="white",
            relief="flat", cursor="hand2", pady=8,
            command=self._run_audit
        )
        self.run_btn.pack(fill="x", pady=(12, 4))

        # Save report button
        self.save_btn = tk.Button(
            frame, text="Save Report (JSON)",
            font=self.f_body, fg=MUTED, bg=SURFACE2,
            activebackground=BORDER, activeforeground=TEXT,
            relief="flat", cursor="hand2", pady=5,
            state="disabled", command=self._save_report
        )
        self.save_btn.pack(fill="x")

        return frame

    # ------------------------------------------------------------------
    def _build_right_panel(self, parent):
        frame = tk.Frame(parent, bg=BG)

        # Top metrics row
        self.metrics_frame = tk.Frame(frame, bg=BG)
        self.metrics_frame.pack(fill="x", pady=(0, 8))
        self._build_metrics_placeholders()

        # Findings notebook
        nb = ttk.Notebook(frame)
        nb.pack(fill="both", expand=True)

        # Tab 1 — Findings table
        findings_tab = tk.Frame(nb, bg=SURFACE)
        nb.add(findings_tab, text="  Findings  ")
        self._build_findings_tab(findings_tab)

        # Tab 2 — Raw JSON
        json_tab = tk.Frame(nb, bg=SURFACE)
        nb.add(json_tab, text="  Raw JSON  ")
        self._build_json_tab(json_tab)

        return frame

    # ------------------------------------------------------------------
    def _build_metrics_placeholders(self):
        for w in self.metrics_frame.winfo_children():
            w.destroy()

        for label, val, fg in [
            ("SCORE",    "--",  MUTED),
            ("CRITICAL", "--",  MUTED),
            ("HIGH",     "--",  MUTED),
            ("MEDIUM",   "--",  MUTED),
            ("LOW",      "--",  MUTED),
            ("FINDINGS", "--",  MUTED),
        ]:
            card = tk.Frame(self.metrics_frame, bg=SURFACE2, padx=12, pady=8)
            card.pack(side="left", fill="y", padx=(0, 6))
            tk.Label(card, text=val,   font=self.f_score if label == "SCORE" else self.f_head,
                     fg=fg, bg=SURFACE2).pack()
            tk.Label(card, text=label, font=self.f_label,
                     fg=MUTED, bg=SURFACE2).pack()

    def _update_metrics(self, report):
        for w in self.metrics_frame.winfo_children():
            w.destroy()

        if report.get("report_type") == "aggregate":
            devices = report.get("devices_audited", 0)
            avg     = report.get("avg_score", 0)
            tc      = report.get("total_critical", 0)
            th      = report.get("total_high", 0)
            tm      = report.get("total_medium", 0)
            tl      = report.get("total_low", 0)
            total_f = tc + th + tm + tl
            cards = [
                ("AVG SCORE", avg,     score_color(avg)),
                ("DEVICES",   devices, ACCENT),
                ("CRITICAL",  tc,      CRIT),
                ("HIGH",      th,      HIGH_C),
                ("MEDIUM",    tm,      MED_C),
                ("FINDINGS",  total_f, TEXT),
            ]
        else:
            score = report.get("score", 0)
            cards = [
                ("SCORE",    score,                      score_color(score)),
                ("CRITICAL", report.get("critical", 0), CRIT),
                ("HIGH",     report.get("high",     0), HIGH_C),
                ("MEDIUM",   report.get("medium",   0), MED_C),
                ("LOW",      report.get("low",      0), LOW_C),
                ("FINDINGS", len(report.get("findings", [])), TEXT),
            ]

        for label, val, fg in cards:
            card = tk.Frame(self.metrics_frame, bg=SURFACE2, padx=14, pady=8)
            card.pack(side="left", fill="y", padx=(0, 6))
            fnt = self.f_score if label in ("SCORE", "AVG SCORE") else self.f_head
            tk.Label(card, text=str(val), font=fnt,
                     fg=fg, bg=SURFACE2).pack()
            tk.Label(card, text=label, font=self.f_label,
                     fg=MUTED, bg=SURFACE2).pack()

    # ------------------------------------------------------------------
    def _build_findings_tab(self, parent):
        cols = ("severity", "rule_id", "section", "description")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings",
                                 selectmode="browse")

        self.tree.heading("severity",    text="Severity")
        self.tree.heading("rule_id",     text="Rule")
        self.tree.heading("section",     text="Section")
        self.tree.heading("description", text="Description")

        self.tree.column("severity",    width=80,  stretch=False)
        self.tree.column("rule_id",     width=90,  stretch=False)
        self.tree.column("section",     width=180, stretch=False)
        self.tree.column("description", width=420, stretch=True)

        scroll_y = ttk.Scrollbar(parent, orient="vertical",   command=self.tree.yview)
        scroll_x = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        # Detail pane below tree
        detail_frame = tk.Frame(parent, bg=SURFACE2, pady=6, padx=8)
        detail_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        tk.Label(detail_frame, text="Remediation:", font=self.f_head,
                 fg=ACCENT, bg=SURFACE2).pack(anchor="w")
        self.detail_text = tk.Text(detail_frame, font=self.f_body, fg=TEXT,
                                   bg=SURFACE2, height=3, wrap="word",
                                   relief="flat", state="disabled",
                                   borderwidth=0)
        self.detail_text.pack(fill="x")

        self.tree.bind("<<TreeviewSelect>>", self._on_finding_select)

        # Tag colours per severity
        for sev, color in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)

    def _on_finding_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])
        iid  = sel[0]
        rem  = self.tree.set(iid, "description")  # store remediation in hidden col
        # Retrieve remediation from stored values dict
        rem = self._remediation_map.get(iid, "")
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("end", rem or "(no remediation)")
        self.detail_text.configure(state="disabled")

    # ------------------------------------------------------------------
    def _build_json_tab(self, parent):
        self.json_text = tk.Text(parent, font=self.f_mono, fg="#a8d8ea",
                                 bg="#0d1117", wrap="none", relief="flat",
                                 borderwidth=0, state="disabled")
        sy = ttk.Scrollbar(parent, orient="vertical",   command=self.json_text.yview)
        sx = ttk.Scrollbar(parent, orient="horizontal", command=self.json_text.xview)
        self.json_text.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.json_text.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

    # ------------------------------------------------------------------
    def _build_status_bar(self):
        bar = tk.Frame(self, bg=SURFACE, pady=3)
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready  -  add config files and click Run Audit")
        tk.Label(bar, textvariable=self.status_var, font=self.f_label,
                 fg=MUTED, bg=SURFACE, anchor="w").pack(side="left", padx=10)
        tk.Label(bar, text=str(BINARY), font=self.f_label,
                 fg=BORDER, bg=SURFACE).pack(side="right", padx=10)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _btn(self, parent, text, cmd, danger=False):
        fg  = CRIT   if danger else TEXT
        bg  = SURFACE2
        abg = "#3a1a1a" if danger else BORDER
        return tk.Button(parent, text=text, font=self.f_body,
                         fg=fg, bg=bg, activeforeground=fg, activebackground=abg,
                         relief="flat", cursor="hand2", padx=8, pady=4,
                         command=cmd)

    def _add_files(self):
        paths = fd.askopenfilenames(
            title="Select config files",
            filetypes=[
                ("Config files", "*.cfg *.conf *.txt *.log"),
                ("All files",    "*.*"),
            ]
        )
        for p in paths:
            if p not in self.selected_files:
                self.selected_files.append(p)
                self.file_listbox.insert("end", Path(p).name)
        self.status_var.set(f"{len(self.selected_files)} file(s) selected")

    def _clear_files(self):
        self.selected_files.clear()
        self.file_listbox.delete(0, "end")
        self.status_var.set("Files cleared")

    def _run_audit(self):
        if not self.selected_files:
            self.status_var.set("No files selected  -  click Add Files first")
            return
        self.run_btn.configure(state="disabled", text="Running...")
        self.status_var.set("Auditing... please wait")
        threading.Thread(target=self._audit_thread, daemon=True).start()

    def _audit_thread(self):
        report = run_audit(
            self.selected_files,
            vendor   = self.vendor_var.get(),
            severity = self.severity_var.get()
        )
        self.after(0, self._audit_done, report)

    def _audit_done(self, report):
        self.run_btn.configure(state="normal", text="RUN AUDIT")

        if "error" in report:
            self.status_var.set(f"Error: {report['error']}")
            self._update_json({"error": report["error"]})
            return

        self.report_data = report
        self.save_btn.configure(state="normal")

        # Update metrics cards
        self._update_metrics(report)

        # Populate findings tree
        self._populate_findings(report)

        # Raw JSON tab
        self._update_json(report)

        findings_count = len(report.get("findings", []))
        if report.get("report_type") == "aggregate":
            findings_count = sum(len(d.get("findings", [])) for d in report.get("devices", []))

        self.status_var.set(
            f"Audit complete  -  {findings_count} finding(s)  |  "
            f"score: {report.get('score', report.get('avg_score', '?'))}/100"
        )

    def _populate_findings(self, report):
        # Clear existing
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._remediation_map = {}

        # Collect findings — device or aggregate
        if report.get("report_type") == "aggregate":
            all_findings = []
            for dev in report.get("devices", []):
                hn = dev.get("hostname", "?")
                for f in dev.get("findings", []):
                    f2 = dict(f)
                    f2["_host"] = hn
                    all_findings.append(f2)
        else:
            all_findings = report.get("findings", [])

        # Sort: CRITICAL first
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(key=lambda f: order.get(f.get("severity", "LOW"), 4))

        for f in all_findings:
            sev  = f.get("severity",    "")
            rid  = f.get("rule_id",     "")
            sec  = f.get("section",     "")
            desc = f.get("description", "")
            rem  = f.get("remediation", "")
            host = f.get("_host", "")

            label = f"[{host}] {desc}" if host else desc

            iid = self.tree.insert("", "end",
                                   values=(sev, rid, sec, label),
                                   tags=(sev,))
            self._remediation_map[iid] = rem

    def _update_json(self, data):
        pretty = json.dumps(data, indent=2, ensure_ascii=False)
        self.json_text.configure(state="normal")
        self.json_text.delete("1.0", "end")
        self.json_text.insert("end", pretty)
        self.json_text.configure(state="disabled")

    def _save_report(self):
        if not self.report_data:
            return
        path = fd.asksaveasfilename(
            title="Save report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("Text", "*.txt")]
        )
        if not path:
            return
        ext = Path(path).suffix.lower()
        if ext == ".json":
            content = json.dumps(self.report_data, indent=2, ensure_ascii=False)
        elif ext == ".csv":
            lines = ["device,vendor,rule_id,severity,section,description,remediation"]
            q = lambda s: '"' + str(s or "").replace('"', '""') + '"'
            devs = self.report_data.get("devices",
                   [self.report_data] if "hostname" in self.report_data else [])
            for dev in devs:
                hn, vn = dev.get("hostname", ""), dev.get("vendor", "")
                for f in dev.get("findings", []):
                    lines.append(",".join([q(hn), q(vn), q(f.get("rule_id", "")),
                                           q(f.get("severity", "")), q(f.get("section", "")),
                                           q(f.get("description", "")), q(f.get("remediation", ""))]))
            content = "\r\n".join(lines)
        else:
            devs = self.report_data.get("devices",
                   [self.report_data] if "hostname" in self.report_data else [])
            lines = ["NET-AUDIT REPORT", "=" * 60]
            for dev in devs:
                lines += [f"Device : {dev.get('hostname','?')}",
                           f"Vendor : {dev.get('vendor','?')}",
                           f"Score  : {dev.get('score','?')}/100", "-" * 40]
                for f in dev.get("findings", []):
                    lines.append(f"  [{f['rule_id']}] {f['severity']} - {f['description']}")
                    lines.append(f"  Fix: {f['remediation']}")
                    lines.append("")
            content = "\n".join(lines)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        self.status_var.set(f"Report saved: {path}")


# ---------------------------------------------------------------------------
# ttk style overrides for dark theme
# ---------------------------------------------------------------------------
def apply_dark_style(root):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(".",
        background    = SURFACE,
        foreground    = TEXT,
        fieldbackground = SURFACE2,
        selectbackground = ACCENT,
        selectforeground = BG,
        font          = ("Segoe UI", 9),
        borderwidth   = 0,
        relief        = "flat",
    )
    style.configure("TCombobox",
        background    = SURFACE2,
        foreground    = TEXT,
        fieldbackground = SURFACE2,
        arrowcolor    = MUTED,
        bordercolor   = BORDER,
    )
    style.configure("Treeview",
        background    = SURFACE,
        foreground    = TEXT,
        fieldbackground = SURFACE,
        rowheight     = 22,
        borderwidth   = 0,
    )
    style.configure("Treeview.Heading",
        background    = SURFACE2,
        foreground    = MUTED,
        font          = ("Segoe UI", 9, "bold"),
        relief        = "flat",
        borderwidth   = 0,
    )
    style.map("Treeview",
        background    = [("selected", ACCENT)],
        foreground    = [("selected", BG)],
    )
    style.configure("TNotebook",
        background    = BG,
        borderwidth   = 0,
        tabmargins    = [0, 0, 0, 0],
    )
    style.configure("TNotebook.Tab",
        background    = SURFACE2,
        foreground    = MUTED,
        padding       = [12, 6],
        borderwidth   = 0,
        font          = ("Segoe UI", 9),
    )
    style.map("TNotebook.Tab",
        background    = [("selected", SURFACE)],
        foreground    = [("selected", TEXT)],
    )
    style.configure("TSeparator", background=BORDER)
    style.configure("TScrollbar",
        background    = SURFACE2,
        troughcolor   = SURFACE,
        arrowcolor    = MUTED,
        borderwidth   = 0,
        relief        = "flat",
    )


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = NetAuditApp()
    apply_dark_style(app)
    app.mainloop()
