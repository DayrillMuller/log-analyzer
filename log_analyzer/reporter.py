"""Rich terminal, JSON, CSV, and self-contained HTML threat report generators."""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from log_analyzer.detector import AnalysisResult, Severity

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
}

_CSV_COLUMNS: list[str] = [
    "rule_id",
    "rule_name",
    "severity",
    "category",
    "source_ip",
    "timestamp",
    "first_seen",
    "last_seen",
    "hit_count",
    "line_numbers",
    "evidence",
    "remediation_hint",
]


def render_terminal_report(
    result: AnalysisResult,
    console: Optional[Console] = None,
) -> None:
    """Render a structured, color-coded threat analysis report to the terminal."""
    out = console if console is not None else Console()
    stats = result.parse_stats

    # 1. Overview & Parse Health panel
    summary_grid = Table.grid(padding=(0, 2))
    summary_grid.add_column(style="bold cyan", justify="right")
    summary_grid.add_column(style="white")

    summary_grid.add_row("Input Source:", result.input_source)
    summary_grid.add_row("Log Format:", result.detected_format)
    summary_grid.add_row(
        "Parse Health:",
        (
            f"{stats.parsed_lines:,} parsed / {stats.total_lines:,} total "
            f"({stats.malformed_lines:,} malformed, {stats.blank_lines:,} blank)"
        ),
    )
    summary_grid.add_row("Allowlisted Events:", f"{result.allowlisted_count:,}")
    summary_grid.add_row("Unique Source IPs:", f"{result.unique_ips:,}")
    summary_grid.add_row("Min Severity Filter:", result.min_severity.name)
    total_hits = sum(f.hit_count for f in result.findings)
    summary_grid.add_row(
        "Total Findings:",
        f"{len(result.findings)} alerts ({total_hits:,} total hits)",
    )
    summary_grid.add_row("Scan Duration:", f"{result.elapsed_seconds:.3f}s")

    border_style = "red" if result.findings else "green"
    out.print(
        Panel(
            summary_grid,
            title="[bold]Log File Analyzer - Threat Report[/bold]",
            border_style=border_style,
            expand=False,
        )
    )

    # 2. Severity breakdown table
    sev_table = Table(
        title="Severity Breakdown",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    sev_table.add_column("Severity", justify="center", min_width=12)
    sev_table.add_column("Alerts", justify="right", min_width=8)

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = result.severity_counts.get(sev.name, 0)
        label = Text(f" {sev.name} ", style=_SEVERITY_STYLES[sev])
        sev_table.add_row(label, str(count))

    out.print(sev_table)

    # 3. Top offending IPs (if any)
    if result.top_offending_ips:
        ip_table = Table(
            title="Top Offending Source IPs",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        ip_table.add_column("Source IP", style="bold white", min_width=16)
        ip_table.add_column("Total Hits", justify="right", style="yellow", min_width=10)
        for ip, count in result.top_offending_ips:
            ip_table.add_row(ip, f"{count:,}")
        out.print(ip_table)

    # 4. Detailed findings table or clean status
    if not result.findings:
        out.print(
            Panel(
                "[bold green]No suspicious patterns or anomalies detected at or above "
                f"{result.min_severity.name} severity.[/bold green]",
                border_style="green",
                expand=False,
            )
        )
        return

    findings_table = Table(
        title="Detailed Security Findings",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
        header_style="bold magenta",
    )
    findings_table.add_column("Severity", justify="center", no_wrap=True)
    findings_table.add_column("Hits", justify="right", style="bold yellow", no_wrap=True)
    findings_table.add_column("Rule", ratio=2, overflow="fold")
    findings_table.add_column("Source / Window", ratio=2, overflow="fold")
    findings_table.add_column("Evidence", ratio=4, overflow="fold")
    findings_table.add_column("Remediation Hint", style="italic", ratio=3, overflow="fold")

    for finding in result.findings:
        sev_badge = Text(f" {finding.severity.name} ", style=_SEVERITY_STYLES[finding.severity])
        rule_cell = Text()
        rule_cell.append(finding.rule_id, style="bold cyan")
        rule_cell.append(f"\n{finding.rule_name}", style="bold white")

        source_cell = Text()
        source_cell.append(finding.source_ip or "N/A", style="green")
        source_cell.append(f"\n{finding.timestamp or 'N/A'}", style="dim")

        findings_table.add_row(
            sev_badge,
            f"{finding.hit_count}x" if finding.hit_count > 1 else "1",
            rule_cell,
            source_cell,
            finding.evidence,
            finding.remediation_hint,
        )

    out.print(findings_table)


def format_json(result: AnalysisResult) -> str:
    """Serialize an AnalysisResult into a pretty-printed JSON string."""
    parse_health = result.parse_stats.to_dict()
    parse_health["allowlisted_lines"] = result.allowlisted_count

    payload = {
        "summary": {
            "input_source": result.input_source,
            "detected_format": result.detected_format,
            "total_lines": result.total_lines,
            "unique_ips": result.unique_ips,
            "min_severity": result.min_severity.name,
            "total_findings": len(result.findings),
            "total_hits": sum(f.hit_count for f in result.findings),
            "parse_health": parse_health,
            "severity_counts": result.severity_counts,
            "top_offending_ips": [
                {"source_ip": ip, "hit_count": count}
                for ip, count in result.top_offending_ips
            ],
            "elapsed_seconds": round(result.elapsed_seconds, 4),
        },
        "findings": [finding.to_dict() for finding in result.findings],
    }
    return json.dumps(payload, indent=2)


def export_json(result: AnalysisResult, output_path: Union[str, Path]) -> Path:
    """Write a JSON threat report to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(format_json(result), encoding="utf-8")
    return path


def format_csv(result: AnalysisResult) -> str:
    """Serialize findings into a CSV string."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for finding in result.findings:
        data = finding.to_dict()
        row = {col: data.get(col, "") for col in _CSV_COLUMNS}
        row["line_numbers"] = ";".join(str(n) for n in data["line_numbers"])
        writer.writerow(row)
    return buffer.getvalue()


def export_csv(result: AnalysisResult, output_path: Union[str, Path]) -> Path:
    """Write a CSV threat report to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(format_csv(result), encoding="utf-8", newline="")
    return path


def format_html(result: AnalysisResult) -> str:
    """Generate a self-contained, dark-mode interactive HTML security report."""
    esc = html.escape
    stats = result.parse_stats
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    total_findings = len(result.findings)
    total_hits = sum(f.hit_count for f in result.findings)

    # Build findings rows with full XSS-safe escaping
    rows_html: list[str] = []
    for finding in result.findings:
        sev = finding.severity.name
        samples = finding.sample_evidence or [finding.evidence]
        samples_markup = "".join(
            f"<li><code>{esc(sample)}</code></li>" for sample in samples[:3]
        )
        time_display = finding.timestamp or "N/A"
        rows_html.append(
            f"""
            <tr data-severity="{esc(sev)}">
              <td><span class="badge sev-{esc(sev.lower())}">{esc(sev)}</span></td>
              <td class="num"><span class="hit-pill">{finding.hit_count}x</span></td>
              <td>
                <div class="rule-id">{esc(finding.rule_id)}</div>
                <div class="rule-name">{esc(finding.rule_name)}</div>
                <div class="rule-cat">{esc(finding.category)}</div>
              </td>
              <td><code>{esc(finding.source_ip or 'N/A')}</code></td>
              <td class="ts">{esc(time_display)}</td>
              <td>
                <div class="evidence-summary">{esc(finding.evidence)}</div>
                <ul class="sample-list">{samples_markup}</ul>
              </td>
              <td class="remediation">{esc(finding.remediation_hint)}</td>
            </tr>
            """
        )

    if rows_html:
        table_body = "\n".join(rows_html)
    else:
        table_body = (
            '<tr><td colspan="7" class="empty-state">'
            f"No suspicious patterns or anomalies detected at or above "
            f"{esc(result.min_severity.name)} severity."
            "</td></tr>"
        )

    top_ips_items = (
        "".join(
            f'<li><code>{esc(ip)}</code><span class="ip-count">{count:,} hits</span></li>'
            for ip, count in result.top_offending_ips
        )
        if result.top_offending_ips
        else '<li class="muted">No offending source IPs recorded.</li>'
    )

    crit_cnt = result.severity_counts.get("CRITICAL", 0)
    high_cnt = result.severity_counts.get("HIGH", 0)
    med_cnt = result.severity_counts.get("MEDIUM", 0)
    low_cnt = result.severity_counts.get("LOW", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Log File Analyzer - Security Report ({esc(Path(result.input_source).name)})</title>
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --surface-2: #1f2631;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #58a6ff;
      --crit: #ff4d4f;
      --high: #f97316;
      --med: #eab308;
      --low: #38bdf8;
      --ok: #22c55e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 24px;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
    }}
    .container {{ max-width: 1440px; margin: 0 auto; }}
    header {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      padding: 20px 24px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 20px;
    }}
    header h1 {{ margin: 0 0 6px; font-size: 1.5rem; letter-spacing: -0.01em; }}
    .meta {{ color: var(--muted); font-size: 0.9rem; }}
    .meta code {{
      color: var(--accent);
      background: var(--surface-2);
      padding: 2px 6px;
      border-radius: 4px;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 18px;
      cursor: pointer;
      transition: transform 0.12s ease, border-color 0.15s ease;
      text-align: left;
      color: inherit;
    }}
    .card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}
    .card.active {{ border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }}
    .card-label {{ font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }}
    .card-value {{ font-size: 2rem; font-weight: 700; margin-top: 4px; }}
    .c-crit {{ color: var(--crit); }}
    .c-high {{ color: var(--high); }}
    .c-med {{ color: var(--med); }}
    .c-low {{ color: var(--low); }}
    .grid-2 {{
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 16px;
      margin-bottom: 20px;
    }}
    @media (max-width: 900px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
    .panel {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 20px;
    }}
    .panel h2 {{ margin: 0 0 12px; font-size: 1rem; color: var(--text); }}
    .health-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 12px;
    }}
    .health-item {{
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
    }}
    .health-item .k {{ font-size: 0.76rem; color: var(--muted); }}
    .health-item .v {{ font-size: 1.2rem; font-weight: 600; margin-top: 2px; }}
    .ip-list {{ list-style: none; padding: 0; margin: 0; }}
    .ip-list li {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 0;
      border-bottom: 1px solid var(--border);
      font-size: 0.9rem;
    }}
    .ip-list li:last-child {{ border-bottom: none; }}
    .ip-count {{ color: var(--med); font-weight: 600; }}
    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 14px;
    }}
    .filter-pills {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .pill {{
      background: var(--surface-2);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 999px;
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 600;
    }}
    .pill.active, .pill:hover {{ border-color: var(--accent); color: var(--accent); }}
    #searchInput {{
      background: var(--surface-2);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 8px;
      min-width: 260px;
      font-size: 0.9rem;
    }}
    #searchInput:focus {{ outline: none; border-color: var(--accent); }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
    th, td {{
      padding: 12px 10px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      text-align: left;
    }}
    th {{
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      background: var(--surface-2);
    }}
    tr:hover td {{ background: rgba(88, 166, 255, 0.04); }}
    .badge {{
      display: inline-block;
      padding: 3px 9px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.04em;
    }}
    .sev-critical {{ background: rgba(255, 77, 79, 0.2); color: var(--crit); border: 1px solid var(--crit); }}
    .sev-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .sev-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--med); border: 1px solid var(--med); }}
    .sev-low {{ background: rgba(56, 189, 248, 0.2); color: var(--low); border: 1px solid var(--low); }}
    .hit-pill {{
      display: inline-block;
      background: var(--surface-2);
      border: 1px solid var(--border);
      color: var(--med);
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.8rem;
    }}
    .rule-id {{ font-weight: 700; color: var(--accent); }}
    .rule-name {{ font-weight: 600; }}
    .rule-cat {{ font-size: 0.75rem; color: var(--muted); }}
    .ts {{ color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.8rem; white-space: nowrap; }}
    .evidence-summary {{ margin-bottom: 6px; }}
    .sample-list {{ margin: 0; padding-left: 16px; color: var(--muted); font-size: 0.8rem; }}
    .sample-list li {{ margin-bottom: 3px; word-break: break-word; }}
    .sample-list code {{ color: #c9d1d9; }}
    .remediation {{ color: #c9d1d9; font-style: italic; }}
    .empty-state {{ text-align: center; padding: 32px; color: var(--ok); font-weight: 600; }}
    .muted {{ color: var(--muted); }}
    .num {{ text-align: right; white-space: nowrap; }}
    footer {{ margin-top: 18px; text-align: right; color: var(--muted); font-size: 0.8rem; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Log File Analyzer &mdash; Security Threat Report</h1>
        <div class="meta">
          Source: <code>{esc(result.input_source)}</code> &middot;
          Format: <code>{esc(result.detected_format)}</code> &middot;
          Min Severity: <code>{esc(result.min_severity.name)}</code> &middot;
          Duration: <code>{result.elapsed_seconds:.3f}s</code>
        </div>
      </div>
      <div class="meta">Generated: <code>{esc(generated_at)}</code></div>
    </header>

    <section class="cards">
      <button type="button" class="card active" data-filter="ALL">
        <div class="card-label">Total Alerts</div>
        <div class="card-value">{total_findings:,}</div>
      </button>
      <button type="button" class="card" data-filter="CRITICAL">
        <div class="card-label">Critical</div>
        <div class="card-value c-crit">{crit_cnt:,}</div>
      </button>
      <button type="button" class="card" data-filter="HIGH">
        <div class="card-label">High</div>
        <div class="card-value c-high">{high_cnt:,}</div>
      </button>
      <button type="button" class="card" data-filter="MEDIUM">
        <div class="card-label">Medium</div>
        <div class="card-value c-med">{med_cnt:,}</div>
      </button>
      <button type="button" class="card" data-filter="LOW">
        <div class="card-label">Low</div>
        <div class="card-value c-low">{low_cnt:,}</div>
      </button>
    </section>

    <section class="grid-2">
      <div class="panel">
        <h2>Parse Health &amp; Telemetry</h2>
        <div class="health-grid">
          <div class="health-item"><div class="k">Total Lines</div><div class="v">{stats.total_lines:,}</div></div>
          <div class="health-item"><div class="k">Parsed Lines</div><div class="v">{stats.parsed_lines:,}</div></div>
          <div class="health-item"><div class="k">Malformed</div><div class="v">{stats.malformed_lines:,}</div></div>
          <div class="health-item"><div class="k">Blank Skipped</div><div class="v">{stats.blank_lines:,}</div></div>
          <div class="health-item"><div class="k">Allowlisted</div><div class="v">{result.allowlisted_count:,}</div></div>
          <div class="health-item"><div class="k">Unique IPs</div><div class="v">{result.unique_ips:,}</div></div>
          <div class="health-item"><div class="k">Total Hits</div><div class="v">{total_hits:,}</div></div>
        </div>
      </div>
      <div class="panel">
        <h2>Top Offending Source IPs</h2>
        <ul class="ip-list">{top_ips_items}</ul>
      </div>
    </section>

    <section class="panel">
      <div class="controls">
        <div class="filter-pills" role="group" aria-label="Severity filter">
          <button type="button" class="pill active" data-filter="ALL">All</button>
          <button type="button" class="pill" data-filter="CRITICAL">Critical</button>
          <button type="button" class="pill" data-filter="HIGH">High</button>
          <button type="button" class="pill" data-filter="MEDIUM">Medium</button>
          <button type="button" class="pill" data-filter="LOW">Low</button>
        </div>
        <input id="searchInput" type="search" placeholder="Filter by rule, IP, evidence, or hint..." />
      </div>
      <div class="table-wrap">
        <table id="findingsTable">
          <thead>
            <tr>
              <th>Severity</th>
              <th class="num">Hits</th>
              <th>Rule</th>
              <th>Source IP</th>
              <th>Time Window</th>
              <th>Evidence &amp; Samples</th>
              <th>Remediation Hint</th>
            </tr>
          </thead>
          <tbody>
            {table_body}
          </tbody>
        </table>
      </div>
    </section>

    <footer>Self-contained report generated by Log File Analyzer</footer>
  </div>

  <script>
    (function () {{
      let activeSeverity = "ALL";
      const searchInput = document.getElementById("searchInput");
      const rows = Array.from(document.querySelectorAll("#findingsTable tbody tr[data-severity]"));
      const controls = Array.from(document.querySelectorAll("[data-filter]"));

      function applyFilters() {{
        const query = (searchInput.value || "").trim().toLowerCase();
        rows.forEach((row) => {{
          const sev = row.getAttribute("data-severity");
          const sevOk = activeSeverity === "ALL" || sev === activeSeverity;
          const textOk = !query || row.textContent.toLowerCase().includes(query);
          row.style.display = sevOk && textOk ? "" : "none";
        }});
      }}

      controls.forEach((el) => {{
        el.addEventListener("click", () => {{
          activeSeverity = el.getAttribute("data-filter") || "ALL";
          controls.forEach((c) => {{
            c.classList.toggle("active", c.getAttribute("data-filter") === activeSeverity);
          }});
          applyFilters();
        }});
      }});

      searchInput.addEventListener("input", applyFilters);
    }})();
  </script>
</body>
</html>
"""


def export_html(result: AnalysisResult, output_path: Union[str, Path]) -> Path:
    """Write a self-contained HTML threat report to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(format_html(result), encoding="utf-8")
    return path
