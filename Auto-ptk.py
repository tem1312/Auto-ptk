#!/usr/bin/env python3
"""
Auto-ptk.py - Auto-PTK with SQLite + interactive follow-up + profiles

Purpose:
 - Discovers JSON module descriptors.
 - Runs each descriptor via Docker and writes raw output files.
 - Stores run metadata and parsed findings in SQLite.
 - After the first scan, can summarise findings and offer follow-up scans.
 - Supports preset scan profiles (e.g. quick, full, web).

Usage examples:
  python3 Auto-ptk.py --list-modules
  python3 Auto-ptk.py --run --target 10.10.10.10
  python3 Auto-ptk.py --run --target 10.10.10.10 --modules nmap-full,nmap-top-tcp
  python3 Auto-ptk.py --run --target 10.10.10.10 --profile quick
  python3 Auto-ptk.py --run --target 10.10.10.10 --profile web --interactive
"""

import argparse
import csv as _csv
import io as _io
import json
import os
import pathlib
import platform
import re
import shutil
import sqlite3
import sys
import traceback
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Dict, Any, TYPE_CHECKING, cast, Optional
from report import generate_html_report


# -------------------------
# Optional Docker imports (runtime + TYPE_CHECKING friendly)
# -------------------------
if TYPE_CHECKING:
    import docker  # type: ignore
    from docker.errors import ImageNotFound as _ImageNotFound  # type: ignore
    from docker.errors import APIError as _APIError  # type: ignore
    from docker.models.containers import Container as _Container  # type: ignore
else:
    # Try runtime import; docker will be None if the package is not installed
    try:
        import docker  # type: ignore
        from docker.errors import ImageNotFound as _ImageNotFound  # type: ignore
        from docker.errors import APIError as _APIError  # type: ignore
        from docker.models.containers import Container as _Container  # type: ignore
    except Exception:
        docker = None  # type: ignore
        _ImageNotFound = Exception  # type: ignore
        _APIError = Exception  # type: ignore
        _Container = Any  # type: ignore

DOCKER_AVAILABLE: bool = docker is not None
ImageNotFound = _ImageNotFound
APIError = _APIError
ContainerType = _Container

# -------------------------
# Exit / error codes returned by run_all()
# -------------------------
# A positive run_id indicates success.
# Negative values indicate a pre-flight failure (no scanning was performed):
EXIT_NO_SDK         = -1  # the 'docker' Python package is not installed
EXIT_NO_DESCRIPTORS = -2  # no module descriptors were supplied
EXIT_NO_DAEMON      = -3  # cannot reach the Docker daemon (Docker Desktop not running, etc.)


def _check_docker_daemon(log_fn=None) -> bool:
    """
    Verify that the Docker daemon is reachable by calling client.ping().

    Returns True if the daemon responded, False otherwise. On failure, prints
    a platform-specific, user-friendly error message (no stack trace) tagged
    with error code EXIT_NO_DAEMON so callers can match against it.
    """
    if not DOCKER_AVAILABLE:
        return False
    try:
        client = docker.from_env()  # type: ignore
        client.ping()  # type: ignore
        return True
    except Exception as e:
        # Build a single-line, user-friendly message. Avoid dumping the raw
        # ConnectionRefusedError / urllib3 chain — it adds noise without info.
        sysname = platform.system()
        if sysname == "Linux":
            hint = "Start Docker with: 'sudo systemctl start docker' (or 'sudo service docker start')."
        elif sysname == "Darwin":
            hint = "Start Docker Desktop from /Applications and wait until the whale icon stops animating."
        else:
            hint = "Start Docker Desktop from the Start menu and wait until the whale icon stops animating."
        msg = (
            f"[error {EXIT_NO_DAEMON}] Cannot connect to the Docker daemon. "
            f"Docker is installed but the daemon is not running or is unreachable.\n"
            f"  Hint: {hint}\n"
            f"  Underlying error: {type(e).__name__}: {e}"
        )
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
        return False

# -------------------------
# Paths & constants
# -------------------------
ROOT = pathlib.Path(__file__).parent.resolve()
MODULE_DIRS = [
    ROOT / "modules" / "recon",
    ROOT / "modules" / "vuln",
    ROOT / "modules" / "Web",
]
REPORTS_DIR = ROOT / "reports"
DB_PATH = ROOT / "auto_ptk.db"
CVE_WATCHLIST_DIR = ROOT / "cve_watchlists"
CVE_WATCHLIST_DEFAULT = CVE_WATCHLIST_DIR / "watchlist.txt"
CVE_WATCHLIST_README = CVE_WATCHLIST_DIR / "README.txt"

# Preset scan profiles: profile_name -> list of module "name" values.
# The strings on the right must match the "name" field inside the module
# descriptor JSON files under modules/recon, modules/vuln and modules/Web.
PROFILES: Dict[str, List[str]] = {
    # Fast "what is up" scan: quick port sweep + service detection
    "quick": [
        "rustscan-fast",
        "nmap-top-tcp",
    ],
    # Broader IP-based reconnaissance + vulnerability probing (no domain-only tools)
    "full": [
        "rustscan-fast",
        "nmap-full",
        "nuclei-scanner",
    ],
    # Web-focused scan for HTTP targets
    "web": [
        "nmap-top-tcp",
        "whatweb-fingerprint",
        "ffuf-dir",
        "nikto-web-scan",
        "nuclei-scanner",
        "nmap-vuln",
    ],
    # Deeper web audit: everything in "web" plus WordPress and TLS checks
    "web-deep": [
        "nmap-top-tcp",
        "whatweb-fingerprint",
        "ffuf-dir",
        "nikto-web-scan",
        "nuclei-scanner",
        "nmap-vuln",
        "wpscan-wordpress",
        "sslscan",
    ],
    # SMB / Windows share enumeration
    "smb": [
        "nmap-top-tcp",
        "nmap-full",
        "enum4linux-ng",
        "smbmap",
        "nmap-vuln",
    ],
    # Focused CVE detection (script-based + template-based)
    "cve": [
        "nmap-vuln",
        "nuclei-scanner",
    ],
    # Domain name enumeration (use with a hostname/domain, not a bare IP)
    "domain": [
        "amass-enum",
        "dnsrecon",
    ],
}

# -------------------------
# Terminal colour & progress bar
# -------------------------

def _enable_windows_ansi() -> bool:
    """Enable ANSI virtual terminal processing on Windows 10+ consoles."""
    try:
        import ctypes
        import ctypes.wintypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.wintypes.DWORD()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            mode.value |= 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(handle, mode)
            return True
    except Exception:
        pass
    return False

def _check_colour_support() -> bool:
    """Return True if stdout is a colour-capable TTY."""
    if not sys.stdout.isatty():
        return False
    if platform.system() == "Windows":
        return _enable_windows_ansi()
    return True

_USE_COLOUR: bool = _check_colour_support()

# Severity → ANSI colour code
_SEV_CODES: Dict[str, str] = {
    "critical": "\033[1;31m",  # bold red
    "high":     "\033[31m",    # red
    "medium":   "\033[33m",    # yellow
    "low":      "\033[34m",    # blue
    "info":     "\033[90m",    # dark grey
}
_COL_OK     = "\033[32m"    # green   — module succeeded
_COL_ERR    = "\033[31m"    # red     — module failed
_COL_SKIP   = "\033[90m"    # grey    — module skipped
_COL_HEADER = "\033[1;36m"  # bold cyan — section headers
_COL_RESET  = "\033[0m"

def _col(text: str, key: str) -> str:
    """Return text wrapped in an ANSI colour code, or plain text if colour is disabled."""
    if not _USE_COLOUR:
        return text
    code = _SEV_CODES.get(key.lower())
    if code is None:
        code = {"ok": _COL_OK, "err": _COL_ERR, "skipped": _COL_SKIP, "header": _COL_HEADER}.get(key.lower(), "")
    return f"{code}{text}{_COL_RESET}" if code else text

def _sev_label(sev: str) -> str:
    """Return a coloured severity label like [HIGH] or [MEDIUM]."""
    s = (sev or "info").lower()
    return _col(f"[{s.upper()}]", s)

def _render_progress(done: int, total: int, name: str, status: str) -> None:
    """
    Write an in-place progress bar to stderr after each module completes.
    Uses carriage-return on TTYs so the bar updates in place; falls back
    to a plain newline when stderr is piped/redirected.
    """
    if total <= 0:
        return
    cols = shutil.get_terminal_size((80, 20)).columns
    bar_width = max(10, min(30, cols - 52))
    filled = round(bar_width * done / total)
    bar = "█" * filled + "░" * (bar_width - filled)
    pct = int(100 * done / total)
    status_col = _col(f"({status})", status)
    line = f"  [{bar}] {done}/{total}  {pct}%  {name} {status_col}"
    if sys.stderr.isatty():
        sys.stderr.write(f"\r{line:<{cols - 2}}")
        if done >= total:
            sys.stderr.write("\n")
        sys.stderr.flush()
    else:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()

# -------------------------
# Utility helpers
# -------------------------
def ensure_dirs() -> None:
    """Create module and reports directories if they do not already exist."""
    for d in MODULE_DIRS:
        d.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "raw").mkdir(parents=True, exist_ok=True)
    ensure_cve_watchlist_files()

def ensure_cve_watchlist_files() -> None:
    """
    Auto-create a CVE watchlist folder + starter files if missing.
    """
    CVE_WATCHLIST_DIR.mkdir(parents=True, exist_ok=True)

    if not CVE_WATCHLIST_README.exists():
        CVE_WATCHLIST_README.write_text(
            "Auto-PTK CVE Watchlists\n"
            "======================\n\n"
            "Put CVE IDs you want to focus on in watchlist.txt (one per line).\n\n"
            "Supported formats (load_cve_watchlist):\n"
            " - .txt  : CVE per line, comments allowed with #\n"
            " - .json : [\"CVE-...\"] OR {\"cves\": [\"CVE-...\"]}\n"
            " - .csv  : any column containing CVE IDs\n\n"
            "Example watchlist.txt:\n"
            "  CVE-2018-10245\n"
            "  CVE-2021-41773\n"
            "  # comments like this are OK\n",
            encoding="utf-8",
        )

    if not CVE_WATCHLIST_DEFAULT.exists():
        CVE_WATCHLIST_DEFAULT.write_text(
            "# Auto-PTK default CVE watchlist\n"
            "# One CVE per line. Lines starting with # are comments.\n"
            "# Example:\n"
            "# CVE-2018-10245\n",
            encoding="utf-8",
        )


def now_tag() -> str:
    """Return a UTC timestamp suitable for tagging runs."""
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


# -------------------------
# SQLite initialisation & helpers
# -------------------------
def init_db() -> sqlite3.Connection:
    """Initialise the SQLite database, creating all tables if they do not exist. Also runs a migration to add the 'severity' column to older databases that predate it."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            tag         TEXT NOT NULL,
            target      TEXT NOT NULL,
            started_at  TEXT NOT NULL,
            finished_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS run_modules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id      INTEGER NOT NULL,
            module_name TEXT NOT NULL,
            image       TEXT NOT NULL,
            status      INTEGER,
            raw_path    TEXT,
            summary     TEXT,
            FOREIGN KEY(run_id) REFERENCES runs(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            run_module_id INTEGER NOT NULL,
            finding_type  TEXT NOT NULL,
            severity      TEXT,
            key           TEXT,
            value         TEXT,
            FOREIGN KEY(run_module_id) REFERENCES run_modules(id)
        )
    """)
    # -------------------------
    # CVE enrichment cache table
    # -------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            cve_id       TEXT PRIMARY KEY,
            source       TEXT NOT NULL,
            title        TEXT,
            description  TEXT,
            cvss         TEXT,
            published    TEXT,
            modified     TEXT,
            fetched_at   TEXT NOT NULL
        )
    """)

    # Migration safety (older DBs)
    cur.execute("PRAGMA table_info(findings)")
    cols = {row[1] for row in cur.fetchall()}
    if "severity" not in cols:
        cur.execute("ALTER TABLE findings ADD COLUMN severity TEXT")

    conn.commit()
    return conn


def store_run(conn: sqlite3.Connection, tag: str, target: str) -> int:
    """Insert a new run row and return its ID."""
    started_at = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO runs(tag, target, started_at) VALUES (?, ?, ?)",
        (tag, target, started_at),
    )
    conn.commit()
    last_id = cur.lastrowid
    if last_id is None:
        raise RuntimeError("Failed to retrieve lastrowid for runs INSERT")
    return last_id


def complete_run(conn: sqlite3.Connection, run_id: int) -> None:
    """Mark a run as finished by setting finished_at."""
    finished_at = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    cur.execute("UPDATE runs SET finished_at = ? WHERE id = ?", (finished_at, run_id))
    conn.commit()


def store_module_result(
    conn: sqlite3.Connection,
    run_id: int,
    descriptor: Dict[str, Any],
    result: Dict[str, Any],
) -> int:
    """Insert a row into run_modules for a single module execution and return its ID."""
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO run_modules(run_id, module_name, image, status, raw_path, summary)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            descriptor.get("name"),
            descriptor.get("image"),
            int(result.get("status", -1)),
            result.get("raw_path"),
            result.get("summary"),
        ),
    )
    conn.commit()
    last_id = cur.lastrowid
    if last_id is None:
        raise RuntimeError("Failed to retrieve lastrowid for run_modules INSERT")
    return last_id


def store_findings(
    conn: sqlite3.Connection,
    run_module_id: int,
    findings: List[Dict[str, Optional[str]]],  # allow None
) -> None:
    """Bulk insert parsed findings for a single run_module."""
    if not findings:
        return
    cur = conn.cursor()
    cur.executemany(
        """
        INSERT INTO findings(run_module_id, finding_type, severity, key, value)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                run_module_id,
                f["finding_type"],
                f.get("severity"),
                f.get("key"),
                f.get("value"),
            )
            for f in findings
        ],
    )
    conn.commit()

def load_cve_watchlist(path: str) -> List[str]:
    """
    Load CVE IDs from a file OR all files in a folder.
    Supports:
      - .txt  (one CVE per line; comments allowed with #)
      - .json (either ["CVE-..."] or {"cves": ["CVE-..."]})
      - .csv  (any column containing CVE IDs)
    Returns a de-duplicated, sorted list of CVEs.
    """
    p = pathlib.Path(path).expanduser().resolve()
    cves: set[str] = set()

    cve_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    def add_from_text(text: str) -> None:
        for m in cve_re.finditer(text):
            cves.add(m.group(0).upper())

    def read_file(fp: pathlib.Path) -> None:
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        if fp.suffix.lower() == ".json":
            try:
                obj = json.loads(text)
                if isinstance(obj, list):
                    for x in obj:
                        if isinstance(x, str):
                            add_from_text(x)
                elif isinstance(obj, dict):
                    arr = obj.get("cves")
                    if isinstance(arr, list):
                        for x in arr:
                            if isinstance(x, str):
                                add_from_text(x)
                    else:
                        # fallback: just regex scan entire json text
                        add_from_text(text)
                else:
                    add_from_text(text)
                return
            except Exception:
                # fallback regex scan
                add_from_text(text)
                return

        if fp.suffix.lower() == ".csv":
            try:
                reader = _csv.reader(_io.StringIO(text))
                for row in reader:
                    add_from_text(" ".join(row))
                return
            except Exception:
                add_from_text(text)
                return

        # default: .txt or anything else => regex scan
        add_from_text(text)

    if p.is_dir():
        for fp in sorted(p.rglob("*")):
            if fp.is_file() and fp.suffix.lower() in (".txt", ".json", ".csv"):
                read_file(fp)
    elif p.is_file():
        read_file(p)
    else:
        raise FileNotFoundError(f"CVE path not found: {p}")

    return sorted(cves)
# -------------------------
# Descriptor loader & filter
# -------------------------
def load_descriptors(dirs: List[pathlib.Path]) -> List[Dict[str, Any]]:
    """
    Load all *.json module descriptors from the given directories.

    Each descriptor must at least have:
      - name: human-readable module name
      - image: Docker image name (e.g., "instrumentisto/nmap")
      - cli: CLI template, using {TARGET} and optional {TAG} placeholders

    Optional fields:
      - parser: string hint for how to parse raw output (e.g., "nmap-open-ports")
      - tags: list of tags (e.g., ["http"]) for follow-up scans / profiles
    """
    descriptors: List[Dict[str, Any]] = []

    for d in dirs:
        if not d.exists():
            continue
        for p in sorted(d.glob("*.json")):
            try:
                j = json.loads(p.read_text(encoding="utf-8"))
                j["_path"] = str(p)
                if "name" not in j or "cli" not in j or "image" not in j:
                    print(f"[WARN] {p.name} missing 'name', 'image' or 'cli' — skipping.")
                    continue
                descriptors.append(j)
            except Exception as e:
                print(f"[WARN] Failed to load {p}: {e}")

    return descriptors


def filter_descriptors_by_names(
    descriptors: List[Dict[str, Any]],
    names: List[str],
) -> List[Dict[str, Any]]:
    """
    Return only descriptors whose 'name' is in the provided list.
    Case-sensitive match, trimmed of surrounding whitespace.
    If names is empty, returns the original descriptor list.
    """
    wanted = {n.strip() for n in names if n.strip()}
    if not wanted:
        return descriptors
    return [d for d in descriptors if str(d.get("name", "")).strip() in wanted]


def apply_profile(
    descriptors: List[Dict[str, Any]],
    profile_name: str,
) -> List[Dict[str, Any]]:
    """
    Map a profile name (e.g. 'quick', 'full', 'web') to a filtered descriptor list.
    Warns if any profile modules are missing from descriptors.
    """
    profile = PROFILES.get(profile_name)
    if profile is None:
        print(f"[profiles] Unknown profile '{profile_name}'. Available profiles: {', '.join(PROFILES.keys())}")
        return []

    profile_set = set(profile)
    selected = [d for d in descriptors if str(d.get("name")) in profile_set]

    missing = profile_set - {str(d.get("name")) for d in selected}
    if missing:
        print(f"[profiles] Warning: the following modules from profile '{profile_name}' "
              f"were not found in descriptors: {', '.join(sorted(missing))}")

    if not selected:
        print(f"[profiles] No modules could be selected for profile '{profile_name}'.")
    else:
        print(f"[profiles] Using profile '{profile_name}' with modules: "
              f"{', '.join(sorted(str(d.get('name')) for d in selected))}")

    return selected


# -------------------------
# Parsing findings from raw output
# -------------------------
def parse_findings(descriptor: Dict[str, Any], raw_path: pathlib.Path) -> List[Dict[str, Optional[str]]]:
    """
    Parse structured findings from a raw output file.

    Output dict keys:
      - finding_type (required)
      - severity (optional)
      - key (optional)
      - value (optional)
    """
    parser_name = descriptor.get("parser")
    findings: List[Dict[str, Optional[str]]] = []

    if not parser_name:
        return findings

    try:
        text = raw_path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return findings

    # 1) Nmap XML / text
    if parser_name in ("nmap-xml", "nmap-open-ports"):
        # Search beyond the first 500 chars to handle tools like RustScan that
        # prepend a large banner before the nmap XML output.
        xml_start = text.find("<?xml")
        if xml_start == -1:
            xml_start = text.find("<nmaprun")
        xml_text = text[xml_start:] if xml_start >= 0 else ""
        if xml_text:
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(xml_text)
                for host in root.findall("host"):
                    for port in host.findall("ports/port"):
                        proto = port.get("protocol", "")
                        portid = port.get("portid", "")
                        state_el = port.find("state")
                        service_el = port.find("service")
                        state = state_el.get("state", "") if state_el is not None else ""
                        service = service_el.get("name", "") if service_el is not None else ""
                        if state == "open":
                            findings.append({
                                "finding_type": "open-port",
                                "severity": "info",
                                "key": f"{portid}/{proto}",
                                "value": f"{state} {service}".strip(),
                            })
                return findings
            except Exception:
                pass

        for line in text.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) < 2:
                    continue
                findings.append({
                    "finding_type": "open-port",
                    "severity": "info",
                    "key": parts[0],
                    "value": f"{parts[1]} {parts[2] if len(parts) > 2 else ''}".strip(),
                })
        return findings

    # 2) Nuclei JSONL (best) with text fallback
    if parser_name == "nuclei-jsonl":
        parsed_any = False
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue

            info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
            sev = (info.get("severity") if isinstance(info, dict) else None) or obj.get("severity")
            template_id = obj.get("template-id") or obj.get("templateID") or obj.get("template_id")
            matched = obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or obj.get("url")

            if template_id and matched:
                findings.append({
                    "finding_type": "nuclei",
                    "severity": str(sev).lower() if sev else "info",
                    "key": str(template_id),
                    "value": str(matched),
                })
                parsed_any = True

        if parsed_any:
            return findings

        parser_name = "nuclei-findings"

    # 3) Nuclei text fallback
    if parser_name == "nuclei-findings":
        nuc_re = re.compile(
            r"^\[(?P<tpl>[^\]]+)\]\s+\[[^\]]+\]\s+\[(?P<sev>critical|high|medium|low|info)\]\s+(?P<url>http[s]?://\S+)",
            re.IGNORECASE,
        )
        for line in text.splitlines():
            m = nuc_re.search(line.strip())
            if not m:
                continue
            findings.append({
                "finding_type": "nuclei",
                "severity": m.group("sev").lower(),
                "key": m.group("tpl"),
                "value": m.group("url"),
            })
        return findings

    # 4) Amass JSON / text
    if parser_name == "amass-json":
        items: list[Any] = []
        try:
            obj = json.loads(text)
            items = obj if isinstance(obj, list) else [obj]
        except Exception:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except Exception:
                    continue

        for it in items:
            if not isinstance(it, dict):
                continue
            name = it.get("name") or it.get("domain") or it.get("fqdn")
            if name:
                findings.append({
                    "finding_type": "domain",
                    "severity": "info",
                    "key": str(name),
                    "value": "discovered",
                })
        return findings

    if parser_name == "amass-domains":
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "." in line:
                findings.append({
                    "finding_type": "domain",
                    "severity": "info",
                    "key": line,
                    "value": "discovered",
                })
        return findings

    # 5) DNSRecon CSV / text
    if parser_name == "dnsrecon-csv":
        reader = _csv.DictReader(_io.StringIO(text))
        for row in reader:
            rtype = (row.get("type") or row.get("Type") or "").strip()
            name = (row.get("name") or row.get("Name") or "").strip()
            target = (row.get("address") or row.get("Address") or row.get("target") or row.get("Target") or "").strip()
            if rtype and name:
                findings.append({
                    "finding_type": "dns-record",
                    "severity": "info",
                    "key": f"{name} {rtype}".strip(),
                    "value": target,
                })
        return findings

    if parser_name == "dnsrecon-records":
        rec_re = re.compile(r"^(?P<name>\S+)\s+\d*\s*IN\s+(?P<rtype>A|AAAA|CNAME|MX|NS|TXT)\s+(?P<target>\S+)", re.IGNORECASE)
        for line in text.splitlines():
            m = rec_re.match(line.strip())
            if not m:
                continue
            findings.append({
                "finding_type": "dns-record",
                "severity": "info",
                "key": f"{m.group('name')} IN {m.group('rtype').upper()}",
                "value": m.group("target"),
            })
        return findings

    # 6) WhatWeb JSON / text
    if parser_name == "whatweb-json":
        try:
            obj = json.loads(text)
        except Exception:
            parser_name = "whatweb-tech"
        else:
            results = obj if isinstance(obj, list) else [obj]
            for r in results:
                if not isinstance(r, dict):
                    continue
                plugins = r.get("plugins", {})
                if not isinstance(plugins, dict):
                    continue
                for plugin_name, plugin_data in plugins.items():
                    if isinstance(plugin_data, dict):
                        strings = plugin_data.get("string")
                        if isinstance(strings, list):
                            for s in strings:
                                findings.append({
                                    "finding_type": "tech",
                                    "severity": "info",
                                    "key": str(plugin_name),
                                    "value": str(s),
                                })
                        else:
                            findings.append({
                                "finding_type": "tech",
                                "severity": "info",
                                "key": str(plugin_name),
                                "value": json.dumps(plugin_data)[:500],
                            })
                    else:
                        findings.append({
                            "finding_type": "tech",
                            "severity": "info",
                            "key": str(plugin_name),
                            "value": str(plugin_data),
                        })
            return findings

    if parser_name == "whatweb-tech":
        plugin_re = re.compile(r"(?P<name>[A-Za-z0-9_\-]+)\[(?P<val>[^\]]+)\]")
        for line in text.splitlines():
            for m in plugin_re.finditer(line):
                findings.append({
                    "finding_type": "tech",
                    "severity": "info",
                    "key": m.group("name"),
                    "value": m.group("val"),
                })
        return findings

    # 7) Nikto JSON / text
    if parser_name == "nikto-json":
        try:
            obj = json.loads(text)
        except Exception:
            return findings

        vulns: list[Any] = []
        if isinstance(obj, dict):
            if isinstance(obj.get("vulnerabilities"), list):
                vulns = obj["vulnerabilities"]
            elif isinstance(obj.get("nikto"), dict) and isinstance(obj["nikto"].get("vulnerabilities"), list):
                vulns = obj["nikto"]["vulnerabilities"]

        for v in vulns:
            if not isinstance(v, dict):
                continue
            msg = v.get("message") or v.get("msg") or v.get("id") or "issue"
            uri = v.get("uri") or v.get("url") or ""
            findings.append({
                "finding_type": "nikto",
                "severity": "medium",
                "key": str(msg)[:250],
                "value": str(uri)[:500] if uri else json.dumps(v)[:500],
            })
        return findings

    if parser_name == "nikto-issues":
        for line in text.splitlines():
            s = line.lstrip()
            if s.startswith("+ ") and "Target IP" not in s and "Target Hostname" not in s and "Target Port" not in s:
                findings.append({
                    "finding_type": "nikto-issue",
                    "severity": "medium",
                    "key": None,
                    "value": s[2:].strip(),
                })
        return findings

    # 8) WPScan JSON / text
    if parser_name == "wpscan-json":
        try:
            obj = json.loads(text)
        except Exception:
            return findings

        def emit_vuln(where: str, v: dict) -> None:
            title = v.get("title") or v.get("name") or "issue"
            sev = v.get("severity") or "medium"
            findings.append({
                "finding_type": "wpscan",
                "severity": str(sev).lower(),
                "key": f"{where}: {title}"[:250],
                "value": json.dumps(v)[:800],
            })

        if isinstance(obj, dict):
            if isinstance(obj.get("vulnerabilities"), list):
                for v in obj["vulnerabilities"]:
                    if isinstance(v, dict):
                        emit_vuln("core", v)

            plugins = obj.get("plugins")
            if isinstance(plugins, dict):
                for pname, pdata in plugins.items():
                    if isinstance(pdata, dict) and isinstance(pdata.get("vulnerabilities"), list):
                        for v in pdata["vulnerabilities"]:
                            if isinstance(v, dict):
                                emit_vuln(f"plugin:{pname}", v)

            themes = obj.get("themes")
            if isinstance(themes, dict):
                for tname, tdata in themes.items():
                    if isinstance(tdata, dict) and isinstance(tdata.get("vulnerabilities"), list):
                        for v in tdata["vulnerabilities"]:
                            if isinstance(v, dict):
                                emit_vuln(f"theme:{tname}", v)
        return findings

    if parser_name == "wpscan-issues":
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("[+]"):
                findings.append({
                    "finding_type": "wpscan-issue",
                    "severity": "medium",
                    "key": None,
                    "value": s[3:].strip(),
                })
        return findings

    # 9) Nmap vuln scripts output (extract CVEs)
    if parser_name == "nmap-vuln-cves":
        cve_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
        for line in text.splitlines():
            m = cve_re.search(line)
            if not m:
                continue
            cve = m.group(0).upper()
            l = line.lower()
            sev = "info"
            if "critical" in l:
                sev = "critical"
            elif "high" in l:
                sev = "high"
            elif "medium" in l:
                sev = "medium"
            elif "low" in l:
                sev = "low"
            findings.append({
                "finding_type": "cve",
                "severity": sev,
                "key": cve,
                "value": line.strip()[:800],
            })
        return findings

    # 10) ffuf JSON
    if parser_name == "ffuf-json":
        try:
            obj = json.loads(text)
        except Exception:
            return findings

        results = obj.get("results", []) if isinstance(obj, dict) else []
        for r in results:
            if not isinstance(r, dict):
                continue
            url = r.get("url") or ""
            status = r.get("status") or ""
            length = r.get("length") or r.get("words") or ""
            redirect = r.get("redirectlocation") or ""
            findings.append({
                "finding_type": "content-path",
                "severity": "info",
                "key": str(status),
                "value": f"{url} length={length} redirect={redirect}".strip(),
            })
        return findings

    # 11) sslscan text
    if parser_name == "sslscan-text":
        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()

            if "sslv2" in low or "sslv3" in low or "tlsv1.0" in low or "tlsv1.1" in low:
                findings.append({
                    "finding_type": "tls-issue",
                    "severity": "medium",
                    "key": "legacy-protocol",
                    "value": s[:800],
                })
                continue

            if "accepted" in low and ("rc4" in low or "des" in low or "3des" in low or "md5" in low):
                findings.append({
                    "finding_type": "tls-issue",
                    "severity": "medium",
                    "key": "weak-cipher",
                    "value": s[:800],
                })
                continue

            if low.startswith("subject:") or low.startswith("issuer:") or low.startswith("not valid"):
                findings.append({
                    "finding_type": "tls-info",
                    "severity": "info",
                    "key": s.split(":", 1)[0],
                    "value": s.split(":", 1)[1].strip() if ":" in s else s[:800],
                })
        return findings

    # 12) enum4linux-ng text
    if parser_name == "enum4linux-text":
        for line in text.splitlines():
            s = line.strip()
            low = s.lower()
            if not s:
                continue

            if "domain name:" in low or "workgroup:" in low:
                findings.append({
                    "finding_type": "smb-info",
                    "severity": "info",
                    "key": "domain/workgroup",
                    "value": s[:800],
                })
                continue

            if "shares:" in low or "print$" in low or "ipc$" in low or "admin$" in low:
                findings.append({
                    "finding_type": "smb-share",
                    "severity": "info",
                    "key": "share",
                    "value": s[:800],
                })
                continue

            if "user" in low and ("rid" in low or "sid" in low):
                findings.append({
                    "finding_type": "smb-user",
                    "severity": "info",
                    "key": "user",
                    "value": s[:800],
                })
                continue

            if "signing" in low:
                sev = "medium" if ("disabled" in low or "false" in low) else "info"
                findings.append({
                    "finding_type": "smb-config",
                    "severity": sev,
                    "key": "signing",
                    "value": s[:800],
                })
        return findings

    # 13) smbmap text
    if parser_name == "smbmap-text":
        for line in text.splitlines():
            s = line.strip()
            low = s.lower()
            if not s:
                continue

            if "disk" in low or "printer" in low or "ipc" in low:
                findings.append({
                    "finding_type": "smb-share",
                    "severity": "info",
                    "key": "share",
                    "value": s[:800],
                })
                continue

            if "read only" in low or "read, write" in low or "no access" in low:
                sev = "medium" if "read, write" in low else "info"
                findings.append({
                    "finding_type": "smb-permission",
                    "severity": sev,
                    "key": "permission",
                    "value": s[:800],
                })
        return findings

    return findings


def summarise_findings(conn: sqlite3.Connection, run_id: int) -> None:
    """Print a colour-coded summary of all parsed findings for a given run."""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT rm.module_name, f.finding_type, COALESCE(f.severity, 'info'), f.key, f.value
        FROM run_modules rm
        JOIN findings f ON f.run_module_id = rm.id
        WHERE rm.run_id = ?
        ORDER BY rm.module_name,
                 CASE lower(COALESCE(f.severity,'info'))
                   WHEN 'critical' THEN 1
                   WHEN 'high'     THEN 2
                   WHEN 'medium'   THEN 3
                   WHEN 'low'      THEN 4
                   ELSE 5
                 END,
                 f.finding_type, f.key
        """,
        (run_id,),
    )
    rows = cur.fetchall()
    if not rows:
        print("[summary] No structured findings parsed; see raw logs for details.")
        return

    print(_col("\n[summary] Parsed findings from initial scan:", "header"))
    current_module = None
    for module_name, finding_type, severity, key, value in rows:
        if module_name != current_module:
            current_module = module_name
            print(_col(f"\n  Module: {module_name}", "header"))
        label = _sev_label(severity)
        if finding_type == "open-port":
            print(f"    {label} Open port: {key}  {_col(value, 'info')}")
        else:
            print(f"    {label} {finding_type}: {key} = {value}")

def export_findings_to_file(
    conn: sqlite3.Connection,
    run_id: int,
    outdir: pathlib.Path,
    tag: str,
) -> pathlib.Path:
    """
    Export parsed findings for a run into a human-readable text file.

    The file will be created as: <outdir>/<tag>-findings.txt
    """
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / f"{tag}-findings.txt"

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
    rows = cur.fetchall()

    if not rows:
        text = "No structured findings parsed for this run.\n"
        out_path.write_text(text, encoding="utf-8")
        return out_path

    lines: list[str] = []
    lines.append(f"Findings summary for run_id={run_id}, tag={tag}\n")
    current_module = None

    for module_name, finding_type, key, value in rows:
        if module_name != current_module:
            current_module = module_name
            lines.append(f"\nModule: {module_name}")
        if finding_type == "open-port":
            lines.append(f"  Open port: {key} -> {value}")
        else:
            lines.append(f"  {finding_type}: {key} = {value}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[summary] Findings written to {out_path}")
    return out_path

# -------------------------
# Docker run helper
# -------------------------
def docker_run_module(descriptor: Dict[str, Any],target: str,tag: str,outdir: pathlib.Path,
                      mem_limit: str = "1g",timeout: int = 600,log_fn=None) -> Dict[str, Any]:
    """
    Run a scanner container using docker-py and capture stdout/stderr into a raw output file.

    NOTE:
      - Only use this on lab targets you own or have explicit permission to test.
    """
    if not DOCKER_AVAILABLE:
        raise RuntimeError("Docker SDK is not available. Install 'docker' Python package.")

    name: str = cast(str, descriptor.get("name", "unknown"))
    image: str = cast(str, descriptor.get("image", ""))
    cli_template: str = cast(str, descriptor.get("cli", ""))
    cmd: str = cli_template.replace("{TARGET}", target).replace("{TAG}", tag)
    # If the caller attached "_cve_ids" to the descriptor, pass them to nuclei via -include-id
    cve_ids = descriptor.get("_cve_ids")
    if name == "nuclei-scanner" and isinstance(cve_ids, list) and cve_ids:
        include = ",".join(str(x).strip().upper() for x in cve_ids if str(x).strip())
        if include:
            cmd = f"{cmd} -include-id {include}"
    outdir.mkdir(parents=True, exist_ok=True)
    raw_path = outdir / f"{tag}-{name}.txt"

    client = docker.from_env()  # type: ignore

    # Host network is only valid on Linux; otherwise we fall back to docker's default bridge.
    network_mode_effective = "host" if platform.system() == "Linux" else None

    try:
        try:
            client.images.get(image)  # type: ignore
        except ImageNotFound:
            print(f"[docker-run] Image {image} not found locally — pulling from Docker Hub...")
            client.images.pull(image)  # type: ignore

        print(
            f"[docker-run] Running container {image} {cmd} "
            f"(mem_limit={mem_limit}, net={network_mode_effective or 'bridge'})"
        )

        run_kwargs = dict(
            image=image,
            command=cmd,
            detach=True,
            remove=False,
            mem_limit=mem_limit,
        )
        if network_mode_effective:
            run_kwargs["network_mode"] = network_mode_effective

        container = client.containers.run(**run_kwargs)  # type: ignore
        container = cast("ContainerType", container)

        logs_bytes = bytearray()
        try:
            for raw in container.logs(stream=True, follow=True):  # type: ignore
                if raw:
                    logs_bytes.extend(raw)
                    try:
                        print(raw.decode(errors="ignore").rstrip())
                    except Exception:
                        pass

            exit_info = container.wait(timeout=timeout)  # type: ignore
            if isinstance(exit_info, dict):
                status_code = int(exit_info.get("StatusCode", 1))
            else:
                try:
                    status_code = int(exit_info)
                except Exception:
                    status_code = 1
        except Exception as e:
            print(f"[docker-run] Error while streaming logs or waiting: {e}")
            traceback.print_exc()
            try:
                status_code = int(container.attrs.get("State", {}).get("ExitCode", 1))  # type: ignore
            except Exception:
                status_code = 1

        try:
            with open(raw_path, "wb") as fh:
                fh.write(bytes(logs_bytes))
        except Exception as e:
            print(f"[docker-run] Failed to write raw output: {e}")

        try:
            container.remove(force=True)  # type: ignore
        except Exception:
            pass

        summary = f"Exit code {status_code}; {len(logs_bytes)} bytes captured"
        return {"status": int(status_code), "raw_path": str(raw_path), "summary": summary}

    except APIError as e:
        print(f"[docker-run] Docker API error: {getattr(e, 'explanation', str(e))}")
        traceback.print_exc()
        return {"status": 1, "raw_path": str(raw_path), "summary": f"Docker API error: {e}"}
    except Exception as e:
        print(f"[docker-run] Unexpected error: {e}")
        traceback.print_exc()
        return {"status": 1, "raw_path": str(raw_path), "summary": f"Unexpected error: {e}"}

def choose_workers(requested: int) -> int:
    """
    Resolve the effective worker count for parallel scanning.
    Clamps the value between 1 and a CPU-derived hard cap to prevent resource exhaustion.
    A requested value of 0 or less means 'auto' (2× CPU count, capped).
    """
    cpu = os.cpu_count() or 4
    auto = max(1, cpu * 2)
    hard_cap = min(32, max(4, cpu * 4))

    if requested <= 0:
        return min(auto, hard_cap)

    return max(1, min(requested, hard_cap))
# -------------------------
# EOL detection + CVE extraction/enrichment helpers
# -------------------------

def _try_parse_version(text: str) -> Optional[tuple[int, ...]]:
    """
    Parse a version like '2.2.14' -> (2,2,14).
    Returns None if not parseable.
    """
    if not text:
        return None
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?", text)
    if not m:
        return None
    parts: list[int] = []
    for g in m.groups():
        if g is None:
            continue
        try:
            parts.append(int(g))
        except Exception:
            return None
    return tuple(parts) if parts else None


def _version_lt(v: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    """
    Compare version tuples with different lengths safely.
    """
    n = max(len(v), len(minimum))
    v2 = v + (0,) * (n - len(v))
    m2 = minimum + (0,) * (n - len(minimum))
    return v2 < m2


def add_eol_findings_for_run(conn: sqlite3.Connection, run_id: int) -> int:
    """
    Scan existing 'tech' findings (from whatweb etc.) and add 'eol-software'
    findings when we detect very old versions.

    This does NOT claim a specific CVE — just flags "out of support / likely outdated".
    """
    # Simple mapping table; extend here when adding new modules that expose
    # new service types (e.g. ftp, rdp, ldap).
    # minimum_supported means "anything older than this is treated as outdated/EOL-ish".
    # Keys are lowercase so lookup via k.lower() is always consistent,
    # regardless of how WhatWeb capitalises the plugin name.
    EOL_RULES: Dict[str, Dict[str, Any]] = {
        "apache":    {"min": (2, 4, 0), "label": "Apache HTTP Server"},
        "php":       {"min": (7, 4, 0), "label": "PHP"},
        "openssl":   {"min": (1, 1, 1), "label": "OpenSSL"},
        "nginx":     {"min": (1, 18, 0), "label": "Nginx"},
        "wordpress": {"min": (6, 0, 0), "label": "WordPress"},
    }

    # Pull run_modules so we can attach EOL findings to a module row.
    # Prefer to attach to whatweb-fingerprint if it exists; else first module.
    cur = conn.cursor()
    cur.execute("""
        SELECT id, module_name
        FROM run_modules
        WHERE run_id = ?
        ORDER BY id ASC
    """, (run_id,))
    rms = cur.fetchall()
    if not rms:
        return 0

    attach_run_module_id = rms[0][0]
    for rm_id, mname in rms:
        if str(mname).lower() == "whatweb-fingerprint":
            attach_run_module_id = rm_id
            break

    # Pull tech findings for this run
    cur.execute("""
        SELECT f.key, f.value
        FROM findings f
        JOIN run_modules rm ON rm.id = f.run_module_id
        WHERE rm.run_id = ? AND f.finding_type = 'tech'
        ORDER BY f.id ASC
    """, (run_id,))
    tech_rows = cur.fetchall()

    inserted = 0
    for key, val in tech_rows:
        k = str(key or "").strip()
        v = str(val or "").strip()

        # Many whatweb entries look like:
        # key="Apache" value="2.2.14"
        # key="PHP" value="5.3.2-..."
        # key="OpenSSL" value="0.9.8k"
        if not k:
            continue

        rule = EOL_RULES.get(k.lower())
        if not rule:
            continue

        ver = _try_parse_version(v)
        if not ver:
            continue

        if _version_lt(ver, rule["min"]):
            product_label = rule["label"]
            ver_str = ".".join(str(x) for x in ver)

            # Insert as a finding (eol-software)
            cur.execute("""
                INSERT INTO findings(run_module_id, finding_type, severity, key, value)
                VALUES (?, ?, ?, ?, ?)
            """, (
                attach_run_module_id,
                "eol-software",
                "medium",
                f"{product_label} {ver_str}",
                "Detected an outdated version (likely out-of-support). Patch/upgrade recommended.",
            ))
            inserted += 1

    conn.commit()
    return inserted


def extract_detected_cves(conn: sqlite3.Connection, run_id: int) -> List[str]:
    """
    Extract CVE IDs that appear in findings.key (e.g. nuclei key = 'CVE-2018-10245').
    De-duplicates and returns sorted list.
    """
    cur = conn.cursor()
    cur.execute("""
        SELECT DISTINCT f.key
        FROM findings f
        JOIN run_modules rm ON rm.id = f.run_module_id
        WHERE rm.run_id = ?
          AND f.key LIKE 'CVE-%'
        ORDER BY f.key ASC
    """, (run_id,))
    out: set[str] = set()
    for (k,) in cur.fetchall():
        if not k:
            continue
        m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", str(k).upper())
        if m:
            out.add(m.group(0))
    return sorted(out)


def export_detected_cves(conn: sqlite3.Connection, run_id: int, outdir: pathlib.Path, tag: str) -> pathlib.Path:
    """
    Write detected CVEs to reports/raw/<tag>/<tag>-cves.txt (alongside the findings file for the same run).
    """
    cves = extract_detected_cves(conn, run_id)
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / f"{tag}-cves.txt"

    if not cves:
        out_path.write_text("No CVEs detected in structured findings for this run.\n", encoding="utf-8")
        return out_path

    out_path.write_text("\n".join(cves) + "\n", encoding="utf-8")
    return out_path


def _fetch_cve_from_circl(cve_id: str, timeout: int = 12) -> Optional[Dict[str, Any]]:
    """
    CIRCL CVE API (simple + lightweight).
    Returns dict or None on failure.
    """
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Auto-PTK/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
        obj = json.loads(data)
        if isinstance(obj, dict) and obj.get("id"):
            return obj
        return None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None
    except Exception:
        return None


def enrich_cves_into_cache(conn: sqlite3.Connection, cve_ids: List[str], source: str = "circl") -> int:
    """
    Enrich CVEs using API and store results in cve_cache.
    Uses caching: if already in cache, skips.
    Returns number of newly cached CVEs.
    """
    if not cve_ids:
        return 0

    cur = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()

    inserted = 0
    for cve_id in cve_ids:
        cve_id = cve_id.strip().upper()
        if not cve_id:
            continue

        # Skip if cached
        row = cur.execute("SELECT cve_id FROM cve_cache WHERE cve_id = ?", (cve_id,)).fetchone()
        if row:
            continue

        obj = _fetch_cve_from_circl(cve_id)
        if not obj:
            continue

        title = obj.get("summary") or obj.get("title") or ""
        desc = obj.get("summary") or obj.get("description") or ""
        cvss = obj.get("cvss") or obj.get("cvss3") or obj.get("cvssv3") or ""
        pub = obj.get("Published") or obj.get("published") or obj.get("PublishedDate") or ""
        mod = obj.get("Modified") or obj.get("modified") or obj.get("LastModifiedDate") or ""

        cur.execute("""
            INSERT INTO cve_cache(cve_id, source, title, description, cvss, published, modified, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (cve_id, source, str(title)[:400], str(desc)[:2000], str(cvss)[:40], str(pub)[:40], str(mod)[:40], now_iso))
        inserted += 1

    conn.commit()
    return inserted

# -------------------------
# Orchestration
# -------------------------
def run_all(
    descriptors: List[Dict[str, Any]],
    target: str,
    tag: str,
    conn: sqlite3.Connection,
    workers: int = 1,
    log_fn=None,
    progress_fn=None,
    stop_event=None,
) -> int:
    """
    Run module descriptors against the target.

    Supports concurrency via ThreadPoolExecutor.
    'workers' controls how many scans run simultaneously.
    """
    if not DOCKER_AVAILABLE:
        msg = (
            f"[error {EXIT_NO_SDK}] Docker SDK is not available. "
            f"Install it with: pip install docker"
        )
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
        return EXIT_NO_SDK

    # Pre-flight: ensure the Docker daemon is reachable. Without this, the
    # first container.run() would raise an opaque ConnectionRefusedError
    # part-way through scanning. Fail fast with a clean error code instead.
    if not _check_docker_daemon(log_fn=log_fn):
        return EXIT_NO_DAEMON

    outdir = REPORTS_DIR / "raw" / tag
    if not descriptors:
        msg = (
            f"[error {EXIT_NO_DESCRIPTORS}] No descriptors found. "
            f"Add JSON files under modules/recon/, modules/vuln/ or modules/Web/"
        )
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
        return EXIT_NO_DESCRIPTORS

    workers = choose_workers(workers)
    run_id = store_run(conn, tag, target)

    header = f"[run] Running {len(descriptors)} module(s) for target {target} (tag={tag}, run_id={run_id}, workers={workers})"
    print(header)
    if log_fn:
        log_fn(header + "\n")

    if platform.system() != "Linux":
        warn = (
            "[warn] Running on non-Linux host — Docker containers use bridge network mode. "
            "Modules that probe local/LAN targets (nuclei, nmap-full) may miss ports or "
            "return no results because bridge-mode containers cannot reach the host network. "
            "For reliable local-network scanning, run Auto-PTK on a Linux machine."
        )
        print(warn)
        if log_fn:
            log_fn(warn + "\n")

    total = len(descriptors)
    done = 0
    db_lock = threading.Lock()  # Serialise DB writes from concurrent worker threads

    def _run_one(d: Dict[str, Any]) -> Dict[str, Any]:
        """Run a single module descriptor inside a Docker container, store the result in the DB, parse findings, and return a summary dict. Called concurrently by ThreadPoolExecutor."""
        name = d.get("name", "unknown")

        if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
            return {
                "module": name,
                "cmd": "",
                "status": -2,
                "raw_path": "",
                "summary": "Skipped due to stop request",
                "parsed": 0,
            }

        cli_template = d.get("cli", "")
        cmd = cli_template.replace("{TARGET}", target).replace("{TAG}", tag)

        result = docker_run_module(d, target, tag, outdir, mem_limit="1g", timeout=600, log_fn=log_fn)

        with db_lock:
            run_module_id = store_module_result(conn, run_id, d, result)

        parsed_count = 0
        raw_path_value = result.get("raw_path")
        if isinstance(raw_path_value, str):
            raw_path = pathlib.Path(raw_path_value)
            findings = parse_findings(d, raw_path)
            if findings:
                with db_lock:
                    store_findings(conn, run_module_id, findings)
            parsed_count = len(findings)

        return {
            "module": name,
            "cmd": cmd,
            "status": result.get("status"),
            "raw_path": result.get("raw_path"),
            "summary": result.get("summary"),
            "parsed": parsed_count,
        }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(_run_one, d): d for d in descriptors}

        for fut in as_completed(future_map):
            d = future_map[fut]
            name = d.get("name", "unknown")

            try:
                r = fut.result()
            except Exception as e:
                r = {
                    "module": name,
                    "cmd": str(d.get("cli", "")),
                    "status": 1,
                    "raw_path": "",
                    "summary": f"Exception: {e}",
                    "parsed": 0,
                }
                traceback.print_exc()

            done += 1

            status_val = r.get("status")
            if status_val == -2:
                status_txt = "skipped"
            elif status_val == 0:
                status_txt = "ok"
            else:
                status_txt = "err"

            if progress_fn:
                progress_fn(done, total, str(r.get("module")), status_txt)

            status_col = _col(f"status={status_val}", status_txt)
            parsed_col = _col(f"parsed={r['parsed']}", "ok" if r["parsed"] else "info")
            line = f"[done] {r['module']}  {status_col}  {parsed_col}  raw={r['raw_path']}"
            print(line)
            if log_fn:
                log_fn(line + "\n")

            if stop_event is not None and stop_event.is_set():
                msg = "[run] Stop requested: attempting to cancel pending modules (those not yet started)."
                print(msg)
                if log_fn:
                    log_fn(msg + "\n")
                for f in future_map:
                    if not f.done():
                        f.cancel()

    complete_run(conn, run_id)

    try:
        eol_added = add_eol_findings_for_run(conn, run_id)
        if eol_added:
            msg = f"[post] Added {eol_added} EOL/outdated software finding(s)."
            print(msg)
            if log_fn:
                log_fn(msg + "\n")
    except Exception as e:
        msg = f"[post] EOL detection failed: {e}"
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
        traceback.print_exc()

    try:
        findings_path = export_findings_to_file(conn, run_id, outdir, tag)
        msg = f"[post] Findings summary written: {findings_path}"
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
    except Exception as e:
        msg = f"[post] Findings export failed: {e}"
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
        traceback.print_exc()

    try:
        cve_path = export_detected_cves(conn, run_id, outdir, tag)
        msg = f"[post] CVE list written: {cve_path}"
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
    except Exception as e:
        msg = f"[post] CVE extraction/export failed: {e}"
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
        traceback.print_exc()

    try:
        detected = extract_detected_cves(conn, run_id)
        if detected:
            added = enrich_cves_into_cache(conn, detected, source="circl")
            msg = f"[post] CVE enrichment: cached {added} new CVE(s) (source=circl)."
        else:
            msg = "[post] CVE enrichment: no detected CVEs to enrich."
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
    except Exception as e:
        msg = f"[post] CVE enrichment failed: {e}"
        print(msg)
        if log_fn:
            log_fn(msg + "\n")
        traceback.print_exc()

    footer = f"[run] Completed. Raw outputs in: {outdir}"
    print(footer)
    if log_fn:
        log_fn(footer + "\n")
    return run_id


# -------------------------
# Interactive follow-up logic
# -------------------------
def interactive_follow_up(
    conn: sqlite3.Connection,
    run_id: int,
    descriptors: List[Dict[str, Any]],
    target: str,
    tag: str,
) -> None:
    """
    Improved interactive follow-up:
      - Menu-driven (summary, ports, nuclei view, guided follow-up, manual follow-up, rerun last)
      - Guided follow-up suggests modules based on detected services (from open-port findings)
      - Remembers suggestions + last module selection via an interactive_state dict
    """

    # -------------------------
    # Interactive session state
    # -------------------------
    interactive_state: Dict[str, Any] = {
        "last_suggested": [],   # List[Dict[str, Any]] descriptors
        "last_selected": [],    # List[Dict[str, Any]] descriptors
        "last_choice": None,    # str (menu choice)
        "service_tags": set(),  # Set[str]
    }

    def _norm_tags(tags_val: Any) -> set[str]:
        if isinstance(tags_val, list):
            return {str(t).strip().lower() for t in tags_val if str(t).strip()}
        if isinstance(tags_val, str):
            # If someone accidentally used "http,web" string
            return {t.strip().lower() for t in tags_val.split(",") if t.strip()}
        return set()

    def _fetch_open_ports_with_service() -> List[Dict[str, str]]:
        """
        Pull open-port findings from the database. Each row is expected to have:
          key   = "80/tcp"
          value = "open http" (or similar)
        """
        cur = conn.cursor()
        cur.execute(
            """
            SELECT f.key, f.value
            FROM findings f
            JOIN run_modules rm ON rm.id = f.run_module_id
            WHERE rm.run_id = ? AND f.finding_type = 'open-port'
            ORDER BY f.key
            """,
            (run_id,),
        )
        out: List[Dict[str, str]] = []
        for k, v in cur.fetchall():
            out.append({"port": str(k or ""), "service": str(v or "")})
        return out

    def _derive_service_tags(open_ports: List[Dict[str, str]]) -> set[str]:
        """
        Convert open ports/services into the tag set used by module descriptors.
        Extend this mapping when adding new scanners for additional services.
        """
        tags: set[str] = set()

        for row in open_ports:
            port = (row.get("port") or "").lower()
            service = (row.get("service") or "").lower()

            # HTTP-ish
            if "http" in service or port.startswith(("80/", "8080/", "8081/", "443/")):
                tags.update({"http", "web"})

            # SSH
            if "ssh" in service or port.startswith("22/"):
                tags.add("ssh")

            # FTP
            if "ftp" in service or port.startswith("21/"):
                tags.add("ftp")

            # SMB / NetBIOS
            if any(x in service for x in ["smb", "netbios", "microsoft-ds"]) or port.startswith(("139/", "445/")):
                tags.add("smb")

            # Databases
            if "mysql" in service or port.startswith("3306/"):
                tags.add("db")
            if "postgres" in service or port.startswith("5432/"):
                tags.add("db")
            if "ms-sql" in service or port.startswith(("1433/", "1434/")):
                tags.add("db")

            # Mail
            if any(x in service for x in ["smtp", "imap", "pop3"]) or port.startswith(("25/", "110/", "143/", "587/", "993/", "995/")):
                tags.add("mail")

        return tags

    def _suggest_modules_by_tags(tags: set[str]) -> List[Dict[str, Any]]:
        """
        Suggest modules whose descriptor.tags overlaps discovered service tags.
        """
        if not tags:
            return []
        suggested: List[Dict[str, Any]] = []
        for d in descriptors:
            dtags = _norm_tags(d.get("tags", []))
            if dtags & tags:
                suggested.append(d)
        return suggested

    def _print_modules_list(mods: List[Dict[str, Any]]) -> None:
        if not mods:
            print("  (none)")
            return
        for i, d in enumerate(mods, 1):
            print(f"  {i}) {d.get('name')}  tags={d.get('tags', [])}")

    def _show_nuclei_findings() -> None:
        """
        Show nuclei findings with optional severity filter (uses DB f.severity if present).
        """
        sev = input("Severity filter (critical/high/medium/low/info or blank=all): ").strip().lower()

        q = """
            SELECT rm.module_name, COALESCE(f.severity,'info') AS sev, f.key, f.value
            FROM findings f
            JOIN run_modules rm ON rm.id = f.run_module_id
            WHERE rm.run_id = ? AND f.finding_type = 'nuclei'
        """
        params: List[Any] = [run_id]

        if sev:
            q += " AND lower(COALESCE(f.severity,'info')) = ?"
            params.append(sev)

        q += " ORDER BY lower(COALESCE(f.severity,'info')), f.key, f.id"

        rows = conn.execute(q, params).fetchall()
        if not rows:
            print("[interactive] No nuclei findings for this run.")
            return

        print(_col("\n[interactive] Nuclei findings:", "header"))
        for module_name, s, k, v in rows:
            print(f"  {_sev_label(s)} {k} -> {v}  {_col(f'(module={module_name})', 'info')}")

    def _show_detected_cves() -> None:
        cves = extract_detected_cves(conn, run_id)
        if not cves:
            print("[interactive] No CVEs detected in this run.")
            return
        print(_col("\n[interactive] Detected CVEs:", "header"))
        for c in cves:
            print(f"  {_col('-', 'err')} {_col(c, 'high')}")

    def _show_enriched_cves() -> None:
        cves = extract_detected_cves(conn, run_id)
        if not cves:
            print("[interactive] No CVEs detected in this run.")
            return

        rows = conn.execute("""
            SELECT cve_id, COALESCE(cvss,''), COALESCE(title,''), COALESCE(published,'')
            FROM cve_cache
            WHERE cve_id IN ({})
            ORDER BY cve_id ASC
        """.format(",".join("?" for _ in cves)), cves).fetchall()

        if not rows:
            print("[interactive] No enriched CVEs in cache yet. (Run a scan first; enrichment runs after run_all)")
            return

        print(_col("\n[interactive] Enriched CVEs (from cache):", "header"))
        for cve_id, cvss, title, pub in rows:
            cvss_s = str(cvss).strip()
            pub_s = str(pub).strip()
            try:
                cvss_f = float(cvss_s)
                cvss_sev = "critical" if cvss_f >= 9.0 else "high" if cvss_f >= 7.0 else "medium" if cvss_f >= 4.0 else "low"
            except ValueError:
                cvss_sev = "info"
            cvss_col = _col(f"CVSS={cvss_s or 'N/A'}", cvss_sev)
            pub_display = pub_s if pub_s else "N/A"
            print(f"  {_col('-', 'err')} {_col(cve_id, 'high')}  {cvss_col}  {_col(f'Published={pub_display}', 'info')}")
            if title:
                print(f"      {_col(str(title)[:160], 'info')}")

    def _show_eol_findings() -> None:
        rows = conn.execute("""
            SELECT rm.module_name, COALESCE(f.severity,'info'), f.key, f.value
            FROM findings f
            JOIN run_modules rm ON rm.id = f.run_module_id
            WHERE rm.run_id = ? AND f.finding_type = 'eol-software'
            ORDER BY f.id ASC
        """, (run_id,)).fetchall()

        if not rows:
            print("[interactive] No EOL/outdated software findings for this run.")
            return

        print(_col("\n[interactive] Outdated / EOL software signals:", "header"))
        for mod, sev, k, v in rows:
            print(f"  {_sev_label(sev)} {k}  {_col(f'(module={mod})', 'info')}")
            if v:
                print(f"      {_col(v, 'info')}")
                
    def _run_modules(mods: List[Dict[str, Any]], suffix: str) -> None:
        if not mods:
            print("[interactive] No modules to run.")
            return
        follow_tag = f"{tag}-{suffix}"
        interactive_state["last_selected"] = mods[:]  # remember
        print(f"[interactive] Running {len(mods)} module(s) with tag={follow_tag}")
        run_all(mods, target, follow_tag, conn)

    # -------------------------
    # Kick off: show summary once
    # -------------------------
    summarise_findings(conn, run_id)

    # -------------------------
    # Menu loop
    # -------------------------
    while True:
        print(_col("\n=== Interactive Mode ===", "header"))
        print("  1) Show findings summary")
        print("  2) Show open ports")
        print("  3) Show nuclei findings (filter by severity)")
        print("  4) Guided follow-up scan (service-based suggestions)")
        print("  5) Manual follow-up scan (pick modules)")
        print("  6) Show detected CVEs")
        print("  7) Show enriched CVEs (from cache)")
        print("  8) Show outdated/EOL software signals")
        print("  9) Re-run last suggested modules")
        print(" 10) Re-run last selected modules")
        print("  0) Exit")
        choice = input("Select: ").strip()
        interactive_state["last_choice"] = choice

        if choice == "1":
            summarise_findings(conn, run_id)

        elif choice == "2":
            open_ports = _fetch_open_ports_with_service()
            if not open_ports:
                print("[interactive] No open ports recorded.")
            else:
                print(_col("\n[interactive] Open ports:", "header"))
                for row in open_ports:
                    print(f"  {_sev_label('info')} {_col(row['port'], 'ok')}  {row['service']}")

        elif choice == "3":
            _show_nuclei_findings()

        elif choice == "4":
            open_ports = _fetch_open_ports_with_service()
            if not open_ports:
                print("[interactive] No open ports found; cannot do guided follow-up.")
                continue

            tags = _derive_service_tags(open_ports)
            interactive_state["service_tags"] = tags

            print("[interactive] Detected service tags:", ", ".join(sorted(tags)) if tags else "(none)")
            suggested = _suggest_modules_by_tags(tags)
            interactive_state["last_suggested"] = suggested[:]  # remember

            if not suggested:
                print("[interactive] No modules matched detected tags.")
                continue

            print("\n[interactive] Suggested modules:")
            _print_modules_list(suggested)

            run_all_yes = input("Run ALL suggested modules? (y/N): ").strip().lower()
            if run_all_yes == "y":
                _run_modules(suggested, "followup")
            else:
                print("[interactive] Not running suggested modules.")

        elif choice == "5":
            print("\nAvailable modules:")
            _print_modules_list(descriptors)

            raw = input("Enter numbers (e.g., 1,3,7) or blank to cancel: ").strip()
            if not raw:
                print("[interactive] Cancelled.")
                continue

            picks: set[int] = set()
            for part in raw.split(","):
                part = part.strip()
                if part.isdigit():
                    picks.add(int(part))

            chosen = [descriptors[i - 1] for i in sorted(picks) if 1 <= i <= len(descriptors)]
            if not chosen:
                print("[interactive] No valid selections.")
                continue

            print("\n[interactive] Selected modules:")
            _print_modules_list(chosen)
            if input("Run selected modules? (y/N): ").strip().lower() == "y":
                _run_modules(chosen, "manual")
            else:
                print("[interactive] Cancelled.")

        elif choice == "6":
            _show_detected_cves() 

        elif choice == "7":
            _show_enriched_cves()

        elif choice == "8":
            _show_eol_findings()

        elif choice == "9":
            last = interactive_state.get("last_suggested") or []
            if not last:
                print("[interactive] No suggested modules saved yet. Use option 4 first.")
                continue
            print("\n[interactive] Re-running last suggested modules:")
            _print_modules_list(last)
            _run_modules(last, "followup-rerun")

        elif choice == "10":
            last = interactive_state.get("last_selected") or []
            if not last:
                print("[interactive] No previous selection saved yet.")
                continue
            print("\n[interactive] Re-running last selected modules:")
            _print_modules_list(last)
            _run_modules(last, "selected-rerun")

        elif choice == "0":
            print("[interactive] Bye.")
            return

        else:
            print("[interactive] Invalid option.")


# -------------------------
# CLI
# -------------------------
def build_parser() -> argparse.ArgumentParser:
    """Build and return the argparse CLI parser with all flags and the examples epilog."""
    p = argparse.ArgumentParser(
        prog="Auto-ptk.py",
        description="Auto-PTK - automated penetration testing toolkit with SQLite, profiles, and interactive follow-up",
        epilog="""
examples:
  List all available modules and profiles:
    python Auto-ptk.py --list-modules

  Quick port scan against a single IP:
    python Auto-ptk.py --run --target 10.10.10.10 --profile quick

  Full IP-based recon with parallel workers:
    python Auto-ptk.py --run --target 10.10.10.10 --profile full --workers 4

  Web audit with interactive follow-up after the scan:
    python Auto-ptk.py --run --target 10.10.10.10 --profile web --interactive

  Domain enumeration (use a hostname/domain, not a bare IP):
    python Auto-ptk.py --run --target example.com --profile domain

  Run specific modules only:
    python Auto-ptk.py --run --target 10.10.10.10 --modules nmap-top-tcp,nuclei-scanner

  Run with a custom tag and save the HTML report to a custom folder:
    python Auto-ptk.py --run --target 10.10.10.10 --profile quick --tag my-lab --report-dir ./out
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--list-modules", action="store_true", help="List discovered module descriptors")
    p.add_argument("--run", action="store_true", help="Run a scan for selected modules (or all); pass --workers >1 for parallel execution")
    p.add_argument("--target", help="Target IP or hostname (required with --run)")
    p.add_argument("--tag", help="Optional run tag (auto-generated if omitted)")
    p.add_argument(
        "--modules",
        help="Comma-separated list of module names to run (overrides --profile; defaults to all discovered modules if neither flag is given)",
    )
    p.add_argument(
        "--profile",
        help=f"Named scan profile to use (one of: {', '.join(PROFILES.keys())})",
    )
    p.add_argument(
        "--interactive",
        action="store_true",
        help="After initial run, summarise findings and offer follow-up scans",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=1,
        help="How many scanner modules to run in parallel.",
    )
    p.add_argument(
        "--report",
        choices=["none", "html"],
        default="html",
        help="Generate HTML report after a run",
    )
    p.add_argument(
        "--report-dir",
        default=str(REPORTS_DIR),
        help="Directory to write HTML report into",
    )
    return p


def main(argv=None):
    """Entry point: parse CLI arguments, load modules, run the selected scan, generate the HTML report, and optionally open the interactive follow-up menu."""
    argv = argv if argv is not None else sys.argv[1:]
    args = build_parser().parse_args(argv)

    ensure_dirs()
    conn = init_db()
    descriptors = load_descriptors(MODULE_DIRS)

    if args.list_modules:
        if not descriptors:
            print("No module descriptors found. Place JSON files into modules/recon/, modules/vuln/ or modules/Web/")
        else:
            print("Discovered descriptors:")
            for d in descriptors:
                print(
                    f" - {d.get('name')} (image: {d.get('image')}, "
                    f"parser: {d.get('parser','none')}, tags: {d.get('tags', [])}) "
                    f"from {d.get('_path')}"
                )
            print("\nAvailable profiles:", ", ".join(PROFILES.keys()))
        return

    if args.run:
        if not args.target:
            print("Error: --target is required with --run")
            return

        if not DOCKER_AVAILABLE:
            print("Error: Docker SDK is not available. Install it with 'pip install docker' and try again.")
            return

        # Decide which descriptors to run:
        # 1) If --modules is given, that takes priority.
        # 2) Else if --profile is given, use the profile.
        # 3) Else, run all descriptors.
        selected_descriptors = descriptors

        if args.modules:
            module_names = [m.strip() for m in args.modules.split(",")]
            selected_descriptors = filter_descriptors_by_names(descriptors, module_names)
            if not selected_descriptors:
                print(f"[run] No descriptors matched the requested module names: {args.modules}")
                return
            else:
                print("[run] Limiting scan to modules:", ", ".join(m.strip() for m in args.modules.split(",")))

        elif args.profile:
            selected_descriptors = apply_profile(descriptors, args.profile)
            if not selected_descriptors:
                return  # error already printed in apply_profile

        tag = args.tag or now_tag()

        workers = args.workers
        if workers <= 0:
            cpu = os.cpu_count() or 4
            suggested = min(32, max(1, cpu * 2))
            try:
                resp = input(f"How many scans to run simultaneously? (suggest {suggested}): ").strip()
                if resp:
                    workers = int(resp)
                else:
                    workers = suggested
            except Exception:
                workers = suggested

        run_id = run_all(
            selected_descriptors, args.target, tag, conn,
            workers=workers,
            progress_fn=_render_progress,
        )

        if run_id > 0 and args.report == "html":
            try:
                html_path = generate_html_report(
                    db_path=str(DB_PATH),
                    run_id=run_id,
                    out_dir=str(pathlib.Path(args.report_dir)),
                )
                print(f"[report] HTML written: {html_path}")
            except Exception as e:
                print(f"[report] Failed to generate HTML report: {e}")
                traceback.print_exc()

        if args.interactive and run_id > 0:
            interactive_follow_up(conn, run_id, descriptors, args.target, tag)

        return

    # Default help hint
    print(
        "No action specified. Run with --help to see usage and examples.\n"
        "Quick start:  python Auto-ptk.py --run --target <IP> --profile quick"
    )


if __name__ == "__main__":
    main()