#!/usr/bin/env python3
"""
ptk_gui.py — GUI for Auto-PTK (SQLite + module selection + profiles + parsed findings)

Features:
- Target + Tag inputs
- Profile dropdown (preset module sets)
- Multi-select module list (run only selected modules)
- Optional interactive follow-up toggle
- Optional HTML report generation after each scan (on by default)
- Runs scan on background thread
- Streams stdout to GUI log
- Shows parsed findings from SQLite
- Exports parsed findings to JSON
- Opens generated HTML reports in the default browser
"""

from __future__ import annotations

import sys
import os
import json
import threading
import importlib.util
import pathlib
import sqlite3
from datetime import datetime, timezone
from tkinter import (
    Tk, Frame, Label, Entry, Button, StringVar,ttk, messagebox, IntVar,Listbox ,Scrollbar, Text, END, BOTH, LEFT, RIGHT, X, Y,
     DISABLED, NORMAL
)
import re

# ---------- locate & import the backend ----------
BACKEND_FILENAME_CANDIDATES = ["Auto-ptk.py", "ptk_tool.py", "ptk_mini_tool.py", "Auto_ptk.py"]
HERE = pathlib.Path(__file__).parent.resolve()

def _import_backend():
    """Search for the backend script by filename and import it as a module. Raises FileNotFoundError if none of the candidate filenames are found."""
    for name in BACKEND_FILENAME_CANDIDATES:
        path = HERE / name
        if path.exists():
            spec = importlib.util.spec_from_file_location("ptk_backend", str(path))
            mod = importlib.util.module_from_spec(spec)  # type: ignore
            assert spec and spec.loader
            spec.loader.exec_module(mod)  # type: ignore
            return mod
    raise FileNotFoundError(
        f"Could not find a backend among: {', '.join(BACKEND_FILENAME_CANDIDATES)} in {HERE}"
    )

backend = _import_backend()

# Profiles are loaded from profiles/profiles.json (dict of name -> list of module names)
PROFILES_DIR = HERE / "profiles"
PROFILES_PATH = PROFILES_DIR / "profiles.json"
SETTINGS_PATH = HERE / "gui_settings.json"

def utc_tag() -> str:
    """Return a UTC timestamp string suitable for tagging scan runs."""
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

class TextRedirector:
    """
    File-like object that redirects print() output into a Tk Text widget.

    Background worker threads call write() via sys.stdout; write() schedules
    the actual widget insert onto the Tk main thread via widget.after(0, ...),
    so the Text widget itself is only ever mutated from the main thread.
    """
    def __init__(self, text_widget):
        self.text = text_widget

    def write(self, s: str) -> None:
        """Queue a string to be appended to the Text widget on the Tk main thread."""
        if not s:
            return
        self.text.after(0, self._append, s)

    def flush(self) -> None:
        """No-op; included so this object satisfies the file-like protocol."""
        pass

    def _append(self, s: str) -> None:
        """Insert text at the end of the widget and scroll into view (main thread only)."""
        self.text.insert(END, s)
        self.text.see(END)



# ---------- DB helpers (read-only) ----------
def _db_connect() -> sqlite3.Connection:
    """Open and return a new SQLite connection to the backend database."""
    return sqlite3.connect(backend.DB_PATH)  # type: ignore[attr-defined]

def fetch_run_findings(run_id: int):
    """
    Returns structured findings:
    [
      (module_name, finding_type, key, value),
      ...
    ]
    """
    conn = _db_connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT rm.module_name, f.finding_type, f.key, f.value
            FROM run_modules rm
            JOIN findings f ON f.run_module_id = rm.id
            WHERE rm.run_id = ?
            ORDER BY rm.module_name, f.finding_type, f.key
            """,
            (run_id,),
        )
        return cur.fetchall()
    finally:
        conn.close()

def export_run_findings_json(run_id: int, out_path: pathlib.Path) -> None:
    """Export all findings for a run as a nested JSON file grouped by module and finding type."""
    rows = fetch_run_findings(run_id)
    out = {}
    for module_name, finding_type, key, value in rows:
        out.setdefault(module_name, {}).setdefault(finding_type, []).append(
            {"key": key, "value": value}
        )
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

def fetch_open_ports(run_id: int):
    """Return open-port findings as [(module_name, port_str, service_str), ...]."""
    conn = _db_connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT rm.module_name, f.key, f.value
            FROM run_modules rm
            JOIN findings f ON f.run_module_id = rm.id
            WHERE rm.run_id = ? AND f.finding_type = 'open-port'
            ORDER BY f.key
            """,
            (run_id,),
        )
        return cur.fetchall()
    finally:
        conn.close()

def fetch_nuclei_findings(run_id: int):
    """Return nuclei findings as [(severity, key, value), ...] ordered by severity then key."""
    conn = _db_connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COALESCE(f.severity,'info') AS sev, f.key, f.value
            FROM findings f
            JOIN run_modules rm ON rm.id = f.run_module_id
            WHERE rm.run_id = ? AND f.finding_type = 'nuclei'
            ORDER BY lower(COALESCE(f.severity,'info')), f.key
            """,
            (run_id,),
        )
        return cur.fetchall()
    finally:
        conn.close()

def extract_detected_cves(run_id: int):
    """Scan all finding keys and values for CVE IDs and return a sorted, deduplicated list."""
    conn = _db_connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT f.key, f.value
            FROM findings f
            JOIN run_modules rm ON rm.id = f.run_module_id
            WHERE rm.run_id = ?
            """,
            (run_id,),
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    cve_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    found = set()
    for k, v in rows:
        if k:
            for m in cve_re.findall(str(k)):
                found.add(m.upper())
        if v:
            for m in cve_re.findall(str(v)):
                found.add(m.upper())

    return sorted(found)

def fetch_run_summary(run_id: int):
    """Return a summary dict with counts of modules, findings, open ports, CVEs, and severities."""
    conn = _db_connect()
    try:
        cur = conn.cursor()

        total_findings = cur.execute("""
            SELECT COUNT(*)
            FROM findings f
            JOIN run_modules rm ON rm.id = f.run_module_id
            WHERE rm.run_id = ?
        """, (run_id,)).fetchone()[0]

        total_modules = cur.execute("""
            SELECT COUNT(*)
            FROM run_modules
            WHERE run_id = ?
        """, (run_id,)).fetchone()[0]

        open_ports = cur.execute("""
            SELECT COUNT(*)
            FROM findings f
            JOIN run_modules rm ON rm.id = f.run_module_id
            WHERE rm.run_id = ? AND f.finding_type = 'open-port'
        """, (run_id,)).fetchone()[0]

        cves = cur.execute("""
            SELECT COUNT(*)
            FROM findings f
            JOIN run_modules rm ON rm.id = f.run_module_id
            WHERE rm.run_id = ?
              AND (f.key LIKE 'CVE-%' OR f.finding_type = 'cve')
        """, (run_id,)).fetchone()[0]

        sev_rows = cur.execute("""
            SELECT lower(COALESCE(f.severity, 'info')) AS sev, COUNT(*)
            FROM findings f
            JOIN run_modules rm ON rm.id = f.run_module_id
            WHERE rm.run_id = ?
            GROUP BY lower(COALESCE(f.severity, 'info'))
        """, (run_id,)).fetchall()
    finally:
        conn.close()

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, count in sev_rows:
        if sev in sev_counts:
            sev_counts[sev] = count

    return {
        "total_modules": total_modules,
        "total_findings": total_findings,
        "open_ports": open_ports,
        "cves": cves,
        "severity": sev_counts,
    }



# ---------- GUI ----------
class App(Tk):
    """Main application window for Auto-PTK. Manages module selection, scan execution on a background thread, live log output, findings display, and theme switching."""

    def __init__(self):
        """Initialise all UI widgets, load saved settings, and apply the stored theme."""
        super().__init__()
        self.title("Auto-PTK – GUI (modules + profiles + parsed findings)")
        self.geometry("1050x720")

        # state
        self.descriptors = []
        self.profile_map = {}   # profile_name -> [module_name, ...]
        self.last_run_id = None
        self.last_tag = None
        self.last_report_path = None  # pathlib.Path of the most recent HTML report
        self.interactive_enabled = False
        self.interactive_state = {
        "service_tags": set(),
        "last_suggested": [],
        "last_selected": [],
        }
        self.stop_event = threading.Event()
        self.theme_var = StringVar(value="System")
        self.current_theme = "System"

        # --- top row controls ---
        top = Frame(self)
        top.pack(fill=X, padx=10, pady=8)

        Label(top, text="Target:").pack(side=LEFT)
        self.target_var = StringVar()
        Entry(top, textvariable=self.target_var, width=26).pack(side=LEFT, padx=(6, 16))

        Label(top, text="Tag:").pack(side=LEFT)
        self.tag_var = StringVar()
        Entry(top, textvariable=self.tag_var, width=18).pack(side=LEFT, padx=(6, 16))

        self.interactive_var = StringVar(value="0")
        self.interactive_chk = ttk.Checkbutton(
            top,
            text="Interactive follow-up",
            variable=self.interactive_var,
            onvalue="1",
            offvalue="0",
        )
        self.interactive_chk.pack(side=LEFT, padx=(0, 16))

        # HTML report toggle — when on, an HTML report is generated after each
        # scan completes and written to the backend's reports/ directory.
        self.report_var = StringVar(value="1")
        self.report_chk = ttk.Checkbutton(
            top,
            text="Generate HTML report",
            variable=self.report_var,
            onvalue="1",
            offvalue="0",
        )
        self.report_chk.pack(side=LEFT, padx=(0, 16))

        self.refresh_btn = Button(top, text="Refresh Modules", command=self.refresh_modules)
        self.refresh_btn.pack(side=LEFT)

        self.open_reports_btn = Button(top, text="Open Reports Folder", command=self.open_reports)
        self.open_reports_btn.pack(side=LEFT, padx=(8, 0))

        self.open_last_report_btn = Button(top, text="Open Last Report", command=self.open_last_report)
        self.open_last_report_btn.pack(side=LEFT, padx=(8, 0))
        Label(top, text="Theme:").pack(side=LEFT, padx=(12, 4))
        # --- theme selection ---
        self.theme_combo = ttk.Combobox(
            top,
            textvariable=self.theme_var,
            state="readonly",
            width=10,
            values=["System", "Light", "Dark"],
        )
        self.theme_combo.pack(side=LEFT)

        self.theme_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_theme())

        # --- profiles row ---
        prof = Frame(self)
        prof.pack(fill=X, padx=10, pady=(0, 8))
        Label(prof, text="Profile:").pack(side=LEFT)
        self.profile_var = StringVar(value="Custom")
        self.profile_combo = ttk.Combobox(prof, textvariable=self.profile_var, state="readonly", width=28)
        self.profile_combo.pack(side=LEFT, padx=(6, 10))
        self.profile_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_profile_selection())

        self.reload_profiles_btn = Button(prof, text="Reload Profiles", command=self.load_profiles)
        self.reload_profiles_btn.pack(side=LEFT)

        self.save_profiles_hint = Label(
            prof,
            text="(profiles/profiles.json)",
        )
        self.save_profiles_hint.pack(side=LEFT, padx=(10, 0))

        # --- workers row ---
        wrow = Frame(self)
        wrow.pack(fill=X, padx=10, pady=(0, 8))

        Label(wrow, text="Workers:").pack(side=LEFT)
        self.workers_var = IntVar(value=1)
        self.workers_spin = ttk.Spinbox(wrow, from_=1, to=32, textvariable=self.workers_var, width=6)
        self.workers_spin.pack(side=LEFT, padx=(6, 16))

        self.current_module_var = StringVar(value="Idle")
        Label(wrow, text="Current:").pack(side=LEFT)
        Label(wrow, textvariable=self.current_module_var).pack(side=LEFT, padx=(6, 0))

        # --- module selection ---
        mid = Frame(self)
        mid.pack(fill=X, padx=10, pady=(0, 6))

        Label(mid, text="Modules (multi-select):").pack(anchor="w")
        list_frame = Frame(mid)
        list_frame.pack(fill=X)

        self.modules_list = Listbox(list_frame, height=9, exportselection=False, selectmode="extended")
        self.modules_list.pack(side=LEFT, fill=X, expand=True)

        sb = Scrollbar(list_frame, command=self.modules_list.yview)
        sb.pack(side=RIGHT, fill=Y)
        self.modules_list.config(yscrollcommand=sb.set)

        selbar = Frame(self)
        selbar.pack(fill=X, padx=10, pady=(0, 6))

        Button(selbar, text="Select All", command=self.select_all_modules).pack(side=LEFT)
        Button(selbar, text="Select None", command=self.select_none_modules).pack(side=LEFT, padx=(8, 0))
        Button(selbar, text="Use Selected (Custom)", command=self.set_custom_profile).pack(side=LEFT, padx=(8, 0))

        # --- run controls ---
        runbar = Frame(self)
        runbar.pack(fill=X, padx=10, pady=(0, 6))

        self.run_btn = Button(runbar, text="Run Scan", command=self.run_scan)
        self.run_btn.pack(side=LEFT)

        self.stop_requested = False
        self.stop_btn = Button(runbar, text="Stop (soft)", state=DISABLED, command=self.request_stop)
        self.stop_btn.pack(side=LEFT, padx=(8, 0))

        self.pb = ttk.Progressbar(runbar, mode="determinate", maximum=100)
        self.pb.pack(side=LEFT, fill=X, expand=True, padx=(16, 0))

        # --- tabs: log + findings ---
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))

        log_tab = Frame(self.tabs)
        findings_tab = Frame(self.tabs)
        self.interactive_tab = Frame(self.tabs)

        self.tabs.add(log_tab, text="Live Log")
        self.tabs.add(findings_tab, text="Parsed Findings")
        self.tabs.add(self.interactive_tab, text="Interactive")

        self.log = Text(log_tab, wrap="word")
        self.log.pack(fill=BOTH, expand=True)

        self.findings = Text(findings_tab, wrap="word")
        self.findings.pack(fill=BOTH, expand=True)

        fbtn = Frame(findings_tab)
        fbtn.pack(fill=X, pady=(6, 0))
        Button(fbtn, text="Refresh Findings (last run)", command=self.refresh_findings).pack(side=LEFT)
        Button(fbtn, text="Export Findings JSON", command=self.export_findings_json).pack(side=LEFT, padx=(8, 0))
        Button(fbtn, text="Show Open Ports", command=self.show_open_ports).pack(side=LEFT, padx=(8, 0))
        Button(fbtn, text="Show Nuclei", command=self.show_nuclei).pack(side=LEFT, padx=(8, 0))
        Button(fbtn, text="Show CVEs", command=self.show_cves).pack(side=LEFT, padx=(8, 0))

        # Initialise data and theme before packing remaining interactive tab widgets
        self.load_profiles()
        self.refresh_modules()
        self.apply_theme()

        # --- interactive tab UI ---
        self.int_ports = Text(self.interactive_tab, wrap="word", height=10)
        self.int_ports.pack(fill=BOTH, expand=False)

        int_btns = Frame(self.interactive_tab)
        int_btns.pack(fill=X, pady=(6, 6))

        Button(int_btns, text="Load from last run", command=self.load_interactive).pack(side=LEFT)
        Button(int_btns, text="Run Suggested Modules", command=self.run_suggested_followup).pack(side=LEFT, padx=(8, 0))

        Label(int_btns, text="Manual follow-up modules:").pack(side=LEFT, padx=(16, 6))

        self.int_module_list = Listbox(self.interactive_tab, height=10, exportselection=False, selectmode="extended")
        self.int_module_list.pack(fill=BOTH, expand=True)

        int_btns2 = Frame(self.interactive_tab)
        int_btns2.pack(fill=X, pady=(6, 0))
        Button(int_btns2, text="Run Selected Modules", command=self.run_selected_followup).pack(side=LEFT)
        Button(int_btns2, text="Remember Selected", command=self.remember_selected_followup).pack(side=LEFT, padx=(8, 0))

        # Insert the Summary tab at index 1 so the final tab order is:
        # Live Log, Summary, Parsed Findings, Interactive.
        self.summary_tab = Frame(self.tabs)
        self.tabs.insert(1, self.summary_tab, text="Summary")
        self.summary_text = Text(self.summary_tab, wrap="word")
        self.summary_text.pack(fill=BOTH, expand=True)
        sbtn = Frame(self.summary_tab)
        sbtn.pack(fill=X, pady=(6, 0))
        Button(sbtn, text="Refresh Summary", command=self.refresh_summary).pack(side=LEFT)

        self.load_settings()
        # Re-apply the theme after load_settings so the persisted theme takes
        # effect on first launch (apply_theme() above ran with the default).
        self.apply_theme()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def load_settings(self):
        """Load persisted settings from gui_settings.json and apply them to the UI controls."""
        try:
            data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8")) if SETTINGS_PATH.exists() else {}
        except Exception:
            data = {}
        self.target_var.set(str(data.get("target", "")))
        self.tag_var.set(str(data.get("tag", "")))
        self.theme_var.set(str(data.get("theme", "System")))
        self.workers_var.set(int(data.get("workers", 1) or 1))
        self.profile_var.set(str(data.get("profile", "Custom")))
        self.interactive_var.set("1" if data.get("interactive") else "0")
        # Default the report toggle ON when no preference is stored yet.
        self.report_var.set("1" if data.get("report", True) else "0")

    def save_settings(self):
        """Save the current UI control values to gui_settings.json for next launch."""
        try:
            data = {
                "target": self.target_var.get().strip(),
                "tag": self.tag_var.get().strip(),
                "theme": self.theme_var.get().strip() or "System",
                "workers": int(self.workers_var.get() or 1),
                "profile": self.profile_var.get().strip() or "Custom",
                "interactive": self.interactive_var.get() == "1",
                "report": self.report_var.get() == "1",
            }
            SETTINGS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def on_close(self):
        """Save settings and destroy the window when the user closes the application."""
        self.save_settings()
        self.destroy()

    # --- profiles ---
    def load_profiles(self):
        """Load scan profiles from profiles/profiles.json and populate the profile dropdown."""
        PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        self.profile_map = {}
        if PROFILES_PATH.exists():
            try:
                data = json.loads(PROFILES_PATH.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    # only keep list[str] values
                    for k, v in data.items():
                        if isinstance(k, str) and isinstance(v, list):
                            self.profile_map[k] = [str(x) for x in v]
            except Exception as e:
                messagebox.showerror("Profiles", f"Failed to load profiles.json:\n{e}")

        names = ["Custom"] + sorted(self.profile_map.keys())
        self.profile_combo["values"] = names
        if self.profile_var.get() not in names:
            self.profile_var.set("Custom")

    def apply_profile_selection(self):
        """Highlight the modules in the list that belong to the currently selected profile."""
        prof = self.profile_var.get()
        self.save_settings()
        if prof == "Custom":
            return
        wanted = set(self.profile_map.get(prof, []))
        self.select_none_modules()
        for i, d in enumerate(self.descriptors):
            if d.get("name") in wanted:
                self.modules_list.selection_set(i)

    def set_custom_profile(self):
        """Switch the profile dropdown to 'Custom' so the user's manual selection is preserved."""
        self.profile_var.set("Custom")
        self.save_settings()

    # --- modules ---
    def refresh_modules(self):
        """Reload module descriptors from disk and repopulate the module listbox."""
        self.modules_list.delete(0, END)
        try:
            backend.ensure_dirs()
            self.descriptors = backend.load_descriptors(backend.MODULE_DIRS)
            for d in self.descriptors:
                self.modules_list.insert(END, f"{d.get('name')}  ({d.get('image')})")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load module descriptors:\n{e}")

        # re-apply profile selection if not Custom
        if self.profile_var.get() != "Custom":
            self.apply_profile_selection()

        self.apply_theme()  
    def select_all_modules(self):
        """Select every module in the listbox."""
        self.modules_list.selection_set(0, END)

    def select_none_modules(self):
        """Clear all selections in the module listbox."""
        self.modules_list.selection_clear(0, END)

    def get_selected_descriptors(self):
        """Return the highlighted module descriptors, or all descriptors if none are selected."""
        idxs = list(self.modules_list.curselection())
        if not idxs:
            return self.descriptors
        return [self.descriptors[i] for i in idxs]

    # --- folders ---
    def open_reports(self):
        """Open the reports folder in the system file explorer."""
        try:
            rep = backend.REPORTS_DIR
            rep.mkdir(parents=True, exist_ok=True)
            path = str(rep)
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                os.system(f"open '{path}'")
            else:
                os.system(f"xdg-open '{path}'")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open reports folder:\n{e}")

    def open_last_report(self):
        """Open the most recently generated HTML report in the default browser."""
        if not self.last_report_path or not pathlib.Path(self.last_report_path).exists():
            messagebox.showinfo(
                "No report yet",
                "No HTML report has been generated in this session.\n"
                "Run a scan with 'Generate HTML report' enabled first.",
            )
            return
        try:
            import webbrowser
            webbrowser.open(pathlib.Path(self.last_report_path).as_uri())
        except Exception as e:
            messagebox.showerror("Error", f"Could not open report:\n{e}")

    def _generate_report_for_run(self, run_id: int) -> None:
        """
        Generate an HTML report for a completed run.

        Called from scan worker threads after backend.run_all() returns a valid
        run_id. Writes the report to backend.REPORTS_DIR, logs the path to the
        live-log widget, and stores it as self.last_report_path so the
        'Open Last Report' button can find it.
        """
        if not run_id or run_id <= 0:
            return
        if self.report_var.get() != "1":
            return
        try:
            html_path = backend.generate_html_report(
                db_path=str(backend.DB_PATH),
                run_id=run_id,
                out_dir=str(backend.REPORTS_DIR),
            )
            self.last_report_path = str(html_path)
            print(f"[report] HTML written: {html_path}\n")
        except Exception as e:
            print(f"[report] Failed to generate HTML report: {e}\n")

    # --- run/stop ---
    def request_stop(self):
        """Signal the running scan worker to stop after the current module finishes."""
        # Signals the scan worker to skip any pending modules that haven't started yet
        self.stop_requested = True
        self.stop_event.set()
        self.log.insert(END, "\n[ui] Stop requested (soft). New modules will be skipped.\n")
        self.log.see(END)

    def run_scan(self):
        """Validate inputs, redirect stdout to the log widget, and launch the scan on a background thread."""
        self.stop_requested = False
        self.stop_event.clear()
        target = self.target_var.get().strip()
        tag = self.tag_var.get().strip() or utc_tag()
        interactive = (self.interactive_var.get() == "1")
        self.interactive_enabled = interactive

        if not target:
            messagebox.showwarning("Missing target", "Please enter a target IP/hostname.")
            return

        self.save_settings()
        selected = self.get_selected_descriptors()
        if not selected:
            messagebox.showwarning("No modules", "No modules selected/found.")
            return

        self.run_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.log.delete("1.0", END)
        self.findings.delete("1.0", END)
        self.pb["value"] = 0
        self.current_module_var.set("Starting...")

        def log_fn(msg: str):
            self.log.after(0, lambda: (self.log.insert(END, msg), self.log.see(END)))

        def progress_fn(done: int, total: int, module_name: str, status: str):
            def _u():
                pct = int((done / total) * 100) if total else 100
                self.pb["value"] = pct
                self.current_module_var.set(f"{module_name} ({status})  {done}/{total}")
            self.after(0, _u)


        # Redirect stdout so backend print() calls (including Docker container output)
        # appear in the GUI log widget, not just the terminal.
        self._old_stdout = sys.stdout
        sys.stdout = TextRedirector(self.log)

        def worker():
            try:
                conn = backend.init_db()
                workers = int(self.workers_var.get() or 1)
                run_id = backend.run_all(
                    selected, target, tag, conn,
                    workers=workers,
                    log_fn=log_fn,
                    progress_fn=progress_fn,
                    stop_event=self.stop_event,
                )
                self.last_run_id = run_id
                self.last_tag = tag

                # Pop a dialog for any pre-flight failure so it isn't lost in
                # the log (the most common one is the Docker daemon not running).
                if run_id == getattr(backend, "EXIT_NO_DAEMON", -3):
                    self.after(0, lambda: messagebox.showerror(
                        "Docker daemon not running",
                        "Auto-PTK could not connect to the Docker daemon.\n\n"
                        "Start Docker Desktop (or 'sudo systemctl start docker' on Linux), "
                        "wait until it is fully running, then try again.\n\n"
                        f"Error code: {run_id}"
                    ))
                    return

                print(f"\n[ui] Run complete. run_id={run_id}\n")

                # Generate the HTML report (if enabled) before refreshing
                # the findings panel so the log shows the report path first.
                self._generate_report_for_run(run_id)

                self.after(0, self.refresh_findings)
                self.after(0, self.refresh_summary)

                if self.interactive_enabled and run_id and run_id > 0:
                    self.after(0, self.load_interactive)
                    self.after(0, lambda: self.tabs.select(self.interactive_tab))

            except Exception as e:
                print(f"[ui] Error: {e}\n")
            finally:
                def _done():
                    self.pb.stop()
                    self.run_btn.config(state=NORMAL)
                    self.stop_btn.config(state=DISABLED)
                    sys.stdout = self._old_stdout
                self.after(0, _done)

        threading.Thread(target=worker, daemon=True).start()


    # --- findings ---

    def _ensure_text_tags(self, widget):
        """Configure named colour tags on a Text widget for severity-coded output."""
        widget.tag_config("critical", foreground="#cc0000")
        widget.tag_config("high", foreground="#ff6600")
        widget.tag_config("medium", foreground="#c09000")
        widget.tag_config("low", foreground="#3366cc")
        widget.tag_config("info", foreground="#666666")
        widget.tag_config("header", foreground="#7a2cff")

    def _sev_tag(self, sev: str) -> str:
        """Normalise a severity string to a valid Text widget tag name, defaulting to 'info'."""
        sev = str(sev or "info").lower()
        return sev if sev in {"critical", "high", "medium", "low", "info"} else "info"

    def refresh_findings(self):
        """Query the DB for the last run's findings and display them colour-coded by severity."""
        self.findings.delete("1.0", END)
        self._ensure_text_tags(self.findings)
        if not self.last_run_id or self.last_run_id <= 0:
            self.findings.insert(END, "No completed run yet.\n")
            return

        conn = _db_connect()
        try:
            rows = conn.execute(
                """
                SELECT rm.module_name, f.finding_type, COALESCE(f.severity,'info'), f.key, f.value
                FROM run_modules rm
                JOIN findings f ON f.run_module_id = rm.id
                WHERE rm.run_id = ?
                ORDER BY rm.module_name, f.finding_type, f.key
                """,
                (self.last_run_id,),
            ).fetchall()
        finally:
            conn.close()

        if not rows:
            self.findings.insert(
                END,
                "No parsed findings found in SQLite for this run.\n"
                "This usually means:\n"
                " - the module's 'parser' field does not match one the backend supports, or\n"
                " - the raw output format is not being parsed yet.\n"
            )
            return

        current_module = None
        for module_name, finding_type, severity, key, value in rows:
            if module_name != current_module:
                current_module = module_name
                self.findings.insert(END, f"\nModule: {module_name}\n", "header")
                self.findings.insert(END, "-" * (8 + len(module_name)) + "\n", "header")
            self.findings.insert(END, f"[{str(severity).upper()}] {finding_type}: {key} -> {value}\n", self._sev_tag(severity))

        self.findings.see(END)

    def refresh_summary(self):
        """Query the DB for the last run's summary counts and display them in the Summary tab."""
        self.summary_text.delete("1.0", END)

        if not self.last_run_id or self.last_run_id <= 0:
            self.summary_text.insert(END, "No completed run yet.\n")
            return

        data = fetch_run_summary(self.last_run_id)

        total_modules = data.get("total_modules", 0) if isinstance(data, dict) else 0
        total_findings = data.get("total_findings", 0) if isinstance(data, dict) else 0
        open_ports = data.get("open_ports", 0) if isinstance(data, dict) else 0
        cves = data.get("cves", 0) if isinstance(data, dict) else 0

        severity = data.get("severity", {}) if isinstance(data, dict) else {}
        if not isinstance(severity, dict):
            severity = {}

        self.summary_text.insert(END, f"Run ID: {self.last_run_id}\n")
        self.summary_text.insert(END, f"Tag: {self.last_tag or 'N/A'}\n")
        self.summary_text.insert(END, "\n")
        self.summary_text.insert(END, f"Total Modules Executed: {total_modules}\n")
        self.summary_text.insert(END, f"Total Findings: {total_findings}\n")
        self.summary_text.insert(END, f"Open Ports: {open_ports}\n")
        self.summary_text.insert(END, f"Detected CVEs: {cves}\n")
        self.summary_text.insert(END, "\nSeverity Breakdown:\n")
        self.summary_text.insert(END, f"  Critical: {severity.get('critical', 0)}\n")
        self.summary_text.insert(END, f"  High:     {severity.get('high', 0)}\n")
        self.summary_text.insert(END, f"  Medium:   {severity.get('medium', 0)}\n")
        self.summary_text.insert(END, f"  Low:      {severity.get('low', 0)}\n")
        self.summary_text.insert(END, f"  Info:     {severity.get('info', 0)}\n")

        self.summary_text.see(END)

    def load_interactive(self):
        """Populate the Interactive tab with open ports, nuclei findings, CVEs, and suggested follow-up modules derived from detected service tags."""
        if not self.descriptors:
            self.refresh_modules()

        self.int_ports.delete("1.0", END)
        self.int_module_list.delete(0, END)

        if not self.last_run_id or self.last_run_id <= 0:
            self.int_ports.insert(END, "No completed run yet.\n")
            return

        ports = fetch_open_ports(self.last_run_id)
        nuclei = fetch_nuclei_findings(self.last_run_id)
        cves = extract_detected_cves(self.last_run_id)

        if not ports and not nuclei and not cves:
            self.int_ports.insert(END,
                "No interactive data found for this run yet.\n\n"
                "This usually means no parser extracted structured findings.\n"
                "Check:\n"
                " - the nmap module outputs XML (-oX) or text matching its parser\n"
                " - the nuclei module is outputting JSONL (recommended)\n"
            )
            self.int_ports.see(END)

        tags = self._derive_service_tags(ports)
        self.interactive_state["service_tags"] = tags

        suggested = self._suggest_modules(tags)
        self.interactive_state["last_suggested"] = suggested

        # Render summary
        self.int_ports.insert(END, f"Run ID: {self.last_run_id}\n")
        self.int_ports.insert(END, f"Detected service tags: {', '.join(sorted(tags)) if tags else '(none)'}\n\n")

        self.int_ports.insert(END, "Open Ports:\n")
        if ports:
            for _m, k, v in ports:
                self.int_ports.insert(END, f"  - {k} -> {v}\n")
        else:
            self.int_ports.insert(END, "  (none)\n")

        self.int_ports.insert(END, "\nNuclei Findings:\n")
        if nuclei:
            for sev, key, val in nuclei:
                self.int_ports.insert(END, f"  [{str(sev).upper()}] {key} -> {val}\n")
        else:
            self.int_ports.insert(END, "  (none)\n")

        self.int_ports.insert(END, "\nDetected CVEs:\n")
        if cves:
            for c in cves:
                self.int_ports.insert(END, f"  - {c}\n")
        else:
            self.int_ports.insert(END, "  (none)\n")

        self.int_ports.see(END)

        # Populate module list for manual follow-up
        for d in self.descriptors:
            self.int_module_list.insert(END, f"{d.get('name')}  tags={d.get('tags', [])}")

    def remember_selected_followup(self):
        """Save the currently highlighted modules in the interactive list for later re-use."""
        idxs = list(self.int_module_list.curselection())
        chosen = [self.descriptors[i] for i in idxs] if idxs else []
        self.interactive_state["last_selected"] = chosen
        messagebox.showinfo("Interactive", f"Remembered {len(chosen)} selected module(s).")

    def run_suggested_followup(self):
        """Run the modules that were automatically suggested based on detected service tags."""
        suggested = self.interactive_state.get("last_suggested") or []
        if not suggested:
            messagebox.showwarning("Interactive", "No suggested modules loaded yet. Click 'Load from last run' first.")
            return
        self._run_followup_modules(suggested, suffix="followup")

    def run_selected_followup(self):
        """Run whichever modules the user has manually highlighted in the interactive module list."""
        idxs = list(self.int_module_list.curselection())
        chosen = [self.descriptors[i] for i in idxs] if idxs else []
        if not chosen:
            messagebox.showwarning("Interactive", "Select modules in the list first.")
            return
        self.interactive_state["last_selected"] = chosen
        self._run_followup_modules(chosen, suffix="manual")

    def _run_followup_modules(self, mods, suffix: str):
        """Launch a follow-up scan for the given module list on a background thread, then refresh findings and summary on completion."""
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Missing target", "Please enter a target IP/hostname.")
            return

        base_tag = self.last_tag or (self.tag_var.get().strip() or utc_tag())
        tag = f"{base_tag}-{suffix}"

        self.run_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.pb.start(10)

        def log_fn(msg: str):
            self.log.after(0, lambda: (self.log.insert(END, msg), self.log.see(END)))

        def progress_fn(done: int, total: int, module_name: str, status: str):
            def _u():
                pct = int((done / total) * 100) if total else 100
                self.pb["value"] = pct
                self.current_module_var.set(f"{module_name} ({status})  {done}/{total}")
            self.after(0, _u)

        # Redirect stdout so backend print() calls appear in the log widget
        self._old_stdout = sys.stdout
        sys.stdout = TextRedirector(self.log)

        def worker():
            try:
                conn = backend.init_db()
                workers = int(self.workers_var.get() or 1)
                run_id = backend.run_all(
                    mods, target, tag, conn,
                    workers=workers,
                    log_fn=log_fn,
                    progress_fn=progress_fn,
                    stop_event=self.stop_event,
                )
                self.last_run_id = run_id
                self.last_tag = tag
                print(f"\n[ui] Follow-up complete. run_id={run_id}\n")
                # Generate a fresh HTML report covering the follow-up run
                self._generate_report_for_run(run_id)
                self.after(0, self.refresh_findings)
                self.after(0, self.refresh_summary)
                if self.interactive_enabled:
                    self.after(0, self.load_interactive)
            except Exception as e:
                print(f"[ui] Follow-up error: {e}\n")
            finally:
                def _done():
                    self.pb.stop()
                    self.run_btn.config(state=NORMAL)
                    self.stop_btn.config(state=DISABLED)
                    sys.stdout = self._old_stdout
                self.after(0, _done)

        threading.Thread(target=worker, daemon=True).start()

    def show_open_ports(self):
        """Display only the open-port findings from the last run in the findings panel."""
        self.findings.delete("1.0", END)
        self._ensure_text_tags(self.findings)
        if not self.last_run_id:
            self.findings.insert(END, "No completed run yet.\n")
            return
        conn = _db_connect()
        try:
            rows = conn.execute("""
                SELECT f.key, f.value
                FROM findings f
                JOIN run_modules rm ON rm.id = f.run_module_id
                WHERE rm.run_id = ? AND f.finding_type = 'open-port'
                ORDER BY f.key
            """, (self.last_run_id,)).fetchall()
        finally:
            conn.close()

        if not rows:
            self.findings.insert(END, "No open-port findings.\n")
            return

        self.findings.insert(END, "Open Ports:\n")
        for k, v in rows:
            self.findings.insert(END, f" - {k} -> {v}\n")

    def show_nuclei(self):
        """Display nuclei findings from the last run, with an optional medium-and-above severity filter."""
        self.findings.delete("1.0", END)
        self._ensure_text_tags(self.findings)
        if not self.last_run_id:
            self.findings.insert(END, "No completed run yet.\n")
            return

        sev = messagebox.askquestion("Nuclei severity", "Filter to Medium+ only?\n(Yes = medium/high/critical, No = all)")
        conn = _db_connect()
        try:
            if sev == "yes":
                rows = conn.execute("""
                    SELECT COALESCE(f.severity,'info') as sev, f.key, f.value
                    FROM findings f
                    JOIN run_modules rm ON rm.id = f.run_module_id
                    WHERE rm.run_id = ? AND f.finding_type='nuclei'
                    AND lower(COALESCE(f.severity,'info')) IN ('medium','high','critical')
                    ORDER BY lower(COALESCE(f.severity,'info')), f.key
                """, (self.last_run_id,)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT COALESCE(f.severity,'info') as sev, f.key, f.value
                    FROM findings f
                    JOIN run_modules rm ON rm.id = f.run_module_id
                    WHERE rm.run_id = ? AND f.finding_type='nuclei'
                    ORDER BY lower(COALESCE(f.severity,'info')), f.key
                """, (self.last_run_id,)).fetchall()
        finally:
            conn.close()

        if not rows:
            self.findings.insert(END, "No nuclei findings.\n")
            return

        self.findings.insert(END, "Nuclei Findings:\n", "header")
        for s, k, v in rows:
            self.findings.insert(END, f"[{str(s).upper()}] {k} -> {v}\n", self._sev_tag(s))


    def show_cves(self):
        """Display CVE findings from the last run, enriched with CVSS score and title from the local cache where available."""
        self.findings.delete("1.0", END)
        self._ensure_text_tags(self.findings)
        if not self.last_run_id:
            self.findings.insert(END, "No completed run yet.\n")
            return

        conn = _db_connect()
        try:
            rows = conn.execute(
                """
                SELECT
                    f.finding_type,
                    f.key,
                    f.value,
                    COALESCE(f.severity,'info') AS severity,
                    COALESCE(c.cvss,'') AS cvss,
                    COALESCE(c.title,'') AS title
                FROM findings f
                JOIN run_modules rm ON rm.id = f.run_module_id
                LEFT JOIN cve_cache c ON c.cve_id = f.key
                WHERE rm.run_id = ?
                  AND (
                    f.key LIKE 'CVE-%'
                    OR f.finding_type = 'cve'
                  )
                ORDER BY f.key
                """,
                (self.last_run_id,),
            ).fetchall()
        finally:
            conn.close()

        if not rows:
            self.findings.insert(END, "No CVEs detected in this run.\n")
            return

        self.findings.insert(END, "Detected CVEs:\n", "header")
        for ft, k, v, s, cvss, title in rows:
            self.findings.insert(END, f" - {k} ({str(s).upper()}, {ft})", self._sev_tag(s))
            if cvss:
                self.findings.insert(END, f" CVSS={cvss}")
            self.findings.insert(END, "\n")
            if title:
                self.findings.insert(END, f"   {title}\n")
            if v:
                self.findings.insert(END, f"   {v}\n")

    def _norm_tags(self, tags_val):
        """Normalise a tags value (list or comma-separated string) to a lowercase set of strings."""
        if isinstance(tags_val, list):
            return {str(t).strip().lower() for t in tags_val if str(t).strip()}
        if isinstance(tags_val, str):
            return {t.strip().lower() for t in tags_val.split(",") if t.strip()}
        return set()

    def _derive_service_tags(self, open_ports_rows):
        """
        Derive a set of service tag strings from open-port findings.
        Each row is (module_name, port_str, service_str), e.g. (_, '80/tcp', 'open http').
        """
        tags = set()

        for _mod, port, service in open_ports_rows:
            port = (port or "").lower()
            service = (service or "").lower()

            if "http" in service or port.startswith(("80/", "8080/", "8081/", "443/")):
                tags.update({"http", "web"})
            if "ssh" in service or port.startswith("22/"):
                tags.add("ssh")
            if "ftp" in service or port.startswith("21/"):
                tags.add("ftp")
            if any(x in service for x in ["smb", "netbios", "microsoft-ds"]) or port.startswith(("139/", "445/")):
                tags.add("smb")
            if "mysql" in service or port.startswith("3306/"):
                tags.add("db")
            if "postgres" in service or port.startswith("5432/"):
                tags.add("db")
            if any(x in service for x in ["smtp", "imap", "pop3"]) or port.startswith(("25/", "110/", "143/", "587/", "993/", "995/")):
                tags.add("mail")

        return tags

    def _suggest_modules(self, tags):
        """Return descriptors whose tag list overlaps with the detected service tags."""
        suggested = []
        for d in self.descriptors:
            dtags = self._norm_tags(d.get("tags", []))
            if dtags & tags:
                suggested.append(d)
        return suggested

    def export_findings_json(self):
        """Export the last run's findings to a JSON file in reports/parsed/ and notify the user."""
        if not self.last_run_id or self.last_run_id <= 0:
            messagebox.showwarning("Export", "No completed run to export.")
            return

        outdir = pathlib.Path(backend.REPORTS_DIR) / "parsed"  # type: ignore[attr-defined]
        outdir.mkdir(parents=True, exist_ok=True)

        fname = f"{self.last_tag or utc_tag()}-run{self.last_run_id}-findings.json"
        outpath = outdir / fname

        try:
            export_run_findings_json(self.last_run_id, outpath)
            messagebox.showinfo("Export", f"Exported parsed findings:\n{outpath}")
        except Exception as e:
            messagebox.showerror("Export", f"Failed to export findings:\n{e}")

    def apply_theme(self):
        """
        Apply System / Light / Dark theme to ttk + tk widgets.
        """
        choice = self.theme_var.get().strip() or "System"
        self.current_theme = choice
        self.save_settings()

        style = ttk.Style(self)

        # Use a safe ttk theme as the base
        try:
            if "clam" in style.theme_names():
                style.theme_use("clam")
        except Exception:
            pass

        if choice == "Dark":
            colors = {
                "bg": "#1e1e1e",
                "panel": "#252526",
                "fg": "#f3f3f3",
                "muted_fg": "#c8c8c8",
                "entry_bg": "#2d2d30",
                "select_bg": "#3a3d41",
                "button_bg": "#2d2d30",
                "button_active": "#3a3d41",
                "border": "#3f3f46",
                "insert": "#ffffff",
            }
        else:
            # System and Light share the same light color palette
            colors = {
                "bg": "#f0f0f0",
                "panel": "#ffffff",
                "fg": "#111111",
                "muted_fg": "#333333",
                "entry_bg": "#ffffff",
                "select_bg": "#dbeafe",
                "button_bg": "#f5f5f5",
                "button_active": "#e5e7eb",
                "border": "#cfcfcf",
                "insert": "#000000",
            }

        self.configure(bg=colors["bg"])
        style.configure("TFrame", background=colors["bg"])
        style.configure("TLabel", background=colors["bg"], foreground=colors["fg"])
        style.configure(
            "TButton",
            background=colors["button_bg"],
            foreground=colors["fg"],
            bordercolor=colors["border"],
            focusthickness=1,
            focuscolor=colors["border"],
        )
        style.map(
            "TButton",
            background=[("active", colors["button_active"])],
            foreground=[("active", colors["fg"])],
        )

        style.configure(
            "TCombobox",
            fieldbackground=colors["entry_bg"],
            background=colors["button_bg"],
            foreground=colors["fg"],
            bordercolor=colors["border"],
            arrowcolor=colors["fg"],
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", colors["entry_bg"])],
            foreground=[("readonly", colors["fg"])],
            selectbackground=[("readonly", colors["select_bg"])],
            selectforeground=[("readonly", colors["fg"])],
        )

        style.configure(
            "TSpinbox",
            fieldbackground=colors["entry_bg"],
            background=colors["button_bg"],
            foreground=colors["fg"],
            bordercolor=colors["border"],
            arrowcolor=colors["fg"],
        )

        style.configure(
            "TCheckbutton",
            background=colors["bg"],
            foreground=colors["fg"],
        )

        style.configure(
            "TNotebook",
            background=colors["bg"],
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background=colors["button_bg"],
            foreground=colors["fg"],
            padding=(10, 6),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", colors["panel"]), ("active", colors["button_active"])],
            foreground=[("selected", colors["fg"]), ("active", colors["fg"])],
        )

        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=colors["panel"],
            background="#4f8cff" if choice == "Dark" else "#2563eb",
            bordercolor=colors["border"],
            lightcolor="#4f8cff" if choice == "Dark" else "#2563eb",
            darkcolor="#4f8cff" if choice == "Dark" else "#2563eb",
        )

        self._apply_widget_colors(self, colors)

    def _apply_widget_colors(self, parent, colors):
        """
        Recursively recolor classic Tk widgets (Text, Listbox, Entry, Frame, Label, Button, etc.)
        """
        for widget in parent.winfo_children():
            cls = widget.winfo_class()

            try:
                if cls in ("Frame", "Labelframe"):
                    widget.configure(bg=colors["bg"])

                elif cls == "Label":
                    widget.configure(bg=colors["bg"], fg=colors["fg"])

                elif cls == "Button":
                    widget.configure(
                        bg=colors["button_bg"],
                        fg=colors["fg"],
                        activebackground=colors["button_active"],
                        activeforeground=colors["fg"],
                        highlightbackground=colors["border"],
                    )

                elif cls == "Entry":
                    widget.configure(
                        bg=colors["entry_bg"],
                        fg=colors["fg"],
                        insertbackground=colors["insert"],
                        highlightbackground=colors["border"],
                        highlightcolor=colors["border"],
                    )

                elif cls == "Text":
                    widget.configure(
                        bg=colors["entry_bg"],
                        fg=colors["fg"],
                        insertbackground=colors["insert"],
                        selectbackground=colors["select_bg"],
                        selectforeground=colors["fg"],
                        highlightbackground=colors["border"],
                        highlightcolor=colors["border"],
                    )

                elif cls == "Listbox":
                    widget.configure(
                        bg=colors["entry_bg"],
                        fg=colors["fg"],
                        selectbackground=colors["select_bg"],
                        selectforeground=colors["fg"],
                        highlightbackground=colors["border"],
                        highlightcolor=colors["border"],
                    )

                elif cls == "Scrollbar":
                    try:
                        widget.configure(
                            bg=colors["button_bg"],
                            activebackground=colors["button_active"],
                            troughcolor=colors["panel"],
                            highlightbackground=colors["border"],
                        )
                    except Exception:
                        pass

            except Exception:
                pass

            self._apply_widget_colors(widget, colors)
    

# ---------- main ----------
if __name__ == "__main__":
    App().mainloop()
