from __future__ import annotations

import html
import pathlib
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _ensure_dir(p: pathlib.Path) -> None:
    """Create a directory and any missing parents, silently if it already exists."""
    p.mkdir(parents=True, exist_ok=True)


def _dt(ts: Optional[str]) -> str:
    """Format an ISO-8601 timestamp for display, returning 'N/A' if absent or unparseable."""
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


def _fetch_report_data(conn: sqlite3.Connection, run_id: int) -> Dict[str, Any]:
    """
    Load all data for a single run from the database.

    Returns a dict with keys:
      - 'run':      the runs row as a dict
      - 'modules':  list of run_modules rows as dicts
      - 'findings': list of findings rows (joined with module name) as dicts
    """
    conn.row_factory = sqlite3.Row

    run = conn.execute(
        "SELECT id, tag, target, started_at, finished_at FROM runs WHERE id = ?",
        (run_id,),
    ).fetchone()
    if not run:
        raise ValueError(f"Run id {run_id} not found in database.")

    modules = conn.execute(
        """
        SELECT id, run_id, module_name, image, status, raw_path, summary
        FROM run_modules
        WHERE run_id = ?
        ORDER BY id ASC
        """,
        (run_id,),
    ).fetchall()

    findings = conn.execute(
        """
        SELECT
            f.id AS finding_id,
            f.run_module_id,
            rm.module_name,
            f.finding_type,
            f.severity,
            f.key,
            f.value
        FROM findings f
        JOIN run_modules rm ON rm.id = f.run_module_id
        WHERE rm.run_id = ?
        ORDER BY rm.module_name, f.finding_type, f.key, f.id
        """,
        (run_id,),
    ).fetchall()

    return {
        "run": dict(run),
        "modules": [dict(m) for m in modules],
        "findings": [dict(f) for f in findings],
    }


def _shorten_path(p: Optional[str]) -> str:
    """Return just the filename portion of a path for compact display in report tables."""
    if not p:
        return ""
    try:
        return pathlib.Path(p).name
    except Exception:
        return p


def render_html_report(data: Dict[str, Any]) -> str:
    """Build and return a complete HTML report string from the data returned by _fetch_report_data."""
    run = data["run"]
    modules = data["modules"]
    findings = data["findings"]

    def esc(x: Any) -> str:
        return html.escape("" if x is None else str(x))

    run_id = run.get("id")
    tag = esc(run.get("tag"))
    target = esc(run.get("target"))
    started = _dt(run.get("started_at"))
    finished = _dt(run.get("finished_at"))

    counts: Dict[str, int] = {}
    for f in findings:
        ft = str(f.get("finding_type", "unknown"))
        counts[ft] = counts.get(ft, 0) + 1

    # Embedded CSS — screen styles first, then @media print overrides
    css = """
    :root {
      --border: #ddd;
      --muted: #555;
      --bg: #fafafa;
      --bg2: #f3f3f3;
      --text: #111;
    }

    body { font-family: Arial, sans-serif; margin: 0; color: var(--text); background: #fff; }
    .wrap { padding: 22px; max-width: 1100px; margin: 0 auto; }
    h1 { margin: 0 0 6px 0; font-size: 28px; letter-spacing: -0.3px; }
    h2 { margin: 22px 0 10px 0; font-size: 18px; }
    .meta { color: #333; font-size: 13px; margin-bottom: 16px; line-height: 1.35; }
    .meta .mono { font-size: 12px; }

    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 14px 0; }
    .card { border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; background: var(--bg); }
    .big { font-size: 24px; font-weight: 700; margin-top: 4px; }
    .small { font-size: 12px; color: var(--muted); }

    .toolbar {
      display: flex;
      gap: 10px;
      align-items: center;
      margin: 10px 0 16px 0;
      flex-wrap: wrap;
    }
    .btn {
      border: 1px solid var(--border);
      background: white;
      border-radius: 10px;
      padding: 8px 10px;
      cursor: pointer;
      font-size: 13px;
    }
    .btn:hover { background: #f8f8f8; }
    .hint { color: var(--muted); font-size: 12px; }

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
    th, td {
      border-bottom: 1px solid #e6e6e6;
      padding: 8px 7px;
      vertical-align: top;
      overflow-wrap: anywhere;
      word-break: break-word;
      white-space: normal;
    }
    th { text-align: left; background: var(--bg2); font-size: 12px; }
    td { font-size: 12px; }

    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
                   "Liberation Mono", "Courier New", monospace;
      font-size: 11px;
      word-break: break-all;
    }

    .pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      border: 1px solid var(--border);
      background: #fff;
    }

    .sev { font-weight: 700; }
    .sev.Critical { color: #990000; }
    .sev.High { color: #b00000; }
    .sev.Medium { color: #b45f06; }
    .sev.Low { color: #0b5394; }
    .sev.Info { color: #0b5394; }

    .muted { color: #666; }
    .hr { height: 1px; background: #eee; margin: 18px 0; }

    @media print {
      @page { size: A4; margin: 14mm; }

      body { background: #fff; }
      .wrap { padding: 0; max-width: none; }
      .toolbar { display: none; }

      .card { break-inside: avoid; page-break-inside: avoid; }
      table { page-break-inside: auto; }
      tr { break-inside: avoid; page-break-inside: avoid; }

      h1 { font-size: 22px; }
      h2 { font-size: 15px; }
      th { font-size: 10px; }
      td { font-size: 10px; }
      .mono { font-size: 9px; }

      /* Remove backgrounds for ink-friendly printing */
      .card { background: #fff; }
      th { background: #fff; border-top: 1px solid #ddd; }
    }
    """

    module_rows: List[str] = []
    for m in modules:
        module_rows.append(
            f"""
            <tr>
              <td class="mono">{esc(m.get("module_name"))}</td>
              <td class="mono">{esc(m.get("image"))}</td>
              <td>{esc(m.get("status"))}</td>
              <td class="mono">{esc(_shorten_path(m.get("raw_path")))}</td>
              <td>{esc(m.get("summary"))}</td>
            </tr>
            """
        )

    finding_rows: List[str] = []
    for f in findings:
        module = f.get("module_name", "")
        ft = str(f.get("finding_type", "unknown"))
        key = f.get("key") or ""
        value = f.get("value") or ""

        sev_raw = f.get("severity")
        sev_norm = str(sev_raw).strip().lower() if sev_raw else "info"
        if sev_norm not in ("critical", "high", "medium", "low", "info"):
            sev_norm = "info"
        sev_display = sev_norm.capitalize()

        finding_rows.append(
            f"""
            <tr>
              <td><span class="sev {sev_display}">{sev_display}</span></td>
              <td>{esc(module)}</td>
              <td>{esc(ft)}</td>
              <td>{esc(key)}</td>
              <td>{esc(value)}</td>
            </tr>
            """
        )

    counts_cards: List[str] = []
    for k in sorted(counts.keys()):
        counts_cards.append(
            f"""
            <div class="card">
              <div class="small">{esc(k)}</div>
              <div class="big">{counts[k]}</div>
            </div>
            """
        )

    toolbar = """
    <div class="toolbar">
      <button class="btn" onclick="window.print()">Print / Save as PDF (browser)</button>
      <div class="hint">Tip: Use your browser’s “Print” to save a PDF with consistent margins.</div>
    </div>
    """

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Auto-PTK Report - Run {esc(run_id)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>{css}</style>
</head>
<body>
  <div class="wrap">
    <h1>Auto-PTK Security Report</h1>
    <div class="meta">
      <div><strong>Run ID:</strong> <span class="mono">{esc(run_id)}</span></div>
      <div><strong>Tag:</strong> <span class="mono">{tag}</span></div>
      <div><strong>Target:</strong> <span class="mono">{target}</span></div>
      <div><strong>Started:</strong> {started} &nbsp; | &nbsp; <strong>Finished:</strong> {finished}</div>
    </div>

    {toolbar}

    <div class="grid">
      <div class="card">
        <div class="small">Total Modules Executed</div>
        <div class="big">{len(modules)}</div>
      </div>
      <div class="card">
        <div class="small">Total Findings</div>
        <div class="big">{len(findings)}</div>
      </div>
    </div>

    {"<div class='grid'>" + "".join(counts_cards) + "</div>" if counts_cards else "<div class='card'>No findings captured.</div>"}

    <h2>Executed Modules</h2>
    <table>
      <thead>
        <tr>
          <th style="width: 16%;">Module</th>
          <th style="width: 16%;">Image</th>
          <th style="width: 6%;">Status</th>
          <th style="width: 32%;">Raw Output</th>
          <th style="width: 30%;">Summary</th>
        </tr>
      </thead>
      <tbody>
        {''.join(module_rows) if module_rows else "<tr><td colspan='5'>No modules recorded.</td></tr>"}
      </tbody>
    </table>

    <h2>Structured Findings</h2>
    <div class="small muted" style="margin-bottom:8px;">
      Severity is read directly from each finding's stored severity value (normalised to critical / high / medium / low / info).
    </div>
    <table>
      <thead>
        <tr>
          <th style="width: 10%;">Severity</th>
          <th style="width: 22%;">Module</th>
          <th style="width: 16%;">Type</th>
          <th style="width: 22%;">Key</th>
          <th style="width: 30%;">Value</th>
        </tr>
      </thead>
      <tbody>
        {''.join(finding_rows) if finding_rows else "<tr><td colspan='5'>No findings recorded.</td></tr>"}
      </tbody>
    </table>

    <div class="hr"></div>
    <div class="small muted">
      Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")} UTC
    </div>
  </div>
</body>
</html>
"""


def write_html(path: pathlib.Path, html_text: str) -> None:
    """Write an HTML string to a file, creating parent directories as needed."""
    _ensure_dir(path.parent)
    path.write_text(html_text, encoding="utf-8")


def generate_html_report(db_path: str, run_id: int, out_dir: str = "reports") -> pathlib.Path:
    """
    Generate an HTML report for a completed run and write it to out_dir/run_<run_id>.html.
    Returns the path to the written file.
    """
    out = pathlib.Path(out_dir)
    _ensure_dir(out)

    # Note: sqlite3.Connection's context manager commits/rolls back but does
    # NOT close the connection. Use try/finally to guarantee close().
    conn = sqlite3.connect(db_path)
    try:
        data = _fetch_report_data(conn, run_id)
    finally:
        conn.close()

    html_text = render_html_report(data)
    html_path = out / f"run_{run_id}.html"
    write_html(html_path, html_text)
    return html_path