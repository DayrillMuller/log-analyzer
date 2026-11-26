"""Unit and integration tests for terminal/JSON/CSV/HTML reporting and CLI behavior."""

from __future__ import annotations

import csv
import gzip
import io
import json
from pathlib import Path

from rich.console import Console

from log_analyzer.cli import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_THREATS_FOUND,
    PROGRESS_THRESHOLD_BYTES,
    main as cli_main,
    should_show_progress,
)
from log_analyzer.detector import DetectionEngine, Severity
from log_analyzer.parsers import ParseStats, detect_log_format, parse_log_file
from log_analyzer.reporter import (
    export_csv,
    export_html,
    export_json,
    format_csv,
    format_html,
    format_json,
    render_terminal_report,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_ACCESS_LOG = PROJECT_ROOT / "sample_logs" / "access.log"
SAMPLE_AUTH_LOG = PROJECT_ROOT / "sample_logs" / "auth.log"


def test_render_terminal_report_with_parse_health_and_empty() -> None:
    engine = DetectionEngine()
    detected = detect_log_format(SAMPLE_ACCESS_LOG)
    assert detected == "nginx"
    stats = ParseStats()
    result = engine.analyze(
        parse_log_file(SAMPLE_ACCESS_LOG, log_format=detected, stats=stats),
        input_source=str(SAMPLE_ACCESS_LOG),
        detected_format=detected,
        parse_stats=stats,
    )

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120)
    render_terminal_report(result, console=console)
    rendered = buf.getvalue()
    assert "Log File Analyzer - Threat Report" in rendered
    assert "Parse Health:" in rendered
    assert "Severity Breakdown" in rendered
    assert "WEB-001" in rendered
    assert "BEH-001" in rendered
    # Verify allowlisted kube-probe /healthz line was tracked
    assert result.allowlisted_count >= 1

    # Render clean report (no findings)
    empty_result = engine.analyze([], input_source="empty.log", detected_format="generic")
    empty_buf = io.StringIO()
    render_terminal_report(empty_result, console=Console(file=empty_buf, force_terminal=False, width=120))
    assert "No suspicious patterns or anomalies detected" in empty_buf.getvalue()


def test_json_csv_and_html_exports(tmp_path: Path) -> None:
    engine = DetectionEngine()
    stats = ParseStats()
    result = engine.analyze(
        parse_log_file(SAMPLE_ACCESS_LOG, log_format="nginx", stats=stats),
        input_source=str(SAMPLE_ACCESS_LOG),
        detected_format="nginx",
        parse_stats=stats,
    )

    # JSON serialization & parse health schema
    json_str = format_json(result)
    parsed_json = json.loads(json_str)
    assert parsed_json["summary"]["detected_format"] == "nginx"
    assert parsed_json["summary"]["total_findings"] == len(result.findings)
    assert parsed_json["summary"]["parse_health"]["parsed_lines"] == stats.parsed_lines
    assert parsed_json["summary"]["parse_health"]["allowlisted_lines"] == result.allowlisted_count
    for finding in parsed_json["findings"]:
        for key in (
            "rule_id",
            "rule_name",
            "severity",
            "source_ip",
            "timestamp",
            "first_seen",
            "last_seen",
            "hit_count",
            "sample_evidence",
            "evidence",
            "remediation_hint",
        ):
            assert key in finding

    json_path = export_json(result, tmp_path / "report.json")
    assert json.loads(json_path.read_text(encoding="utf-8")) == parsed_json

    # CSV serialization & file export
    csv_str = format_csv(result)
    rows = list(csv.DictReader(io.StringIO(csv_str)))
    assert len(rows) == len(result.findings)
    assert "hit_count" in rows[0]

    csv_path = export_csv(result, tmp_path / "report.csv")
    assert csv_path.read_text(encoding="utf-8") == csv_str

    # Self-contained HTML report & XSS escaping verification
    html_str = format_html(result)
    assert "<!DOCTYPE html>" in html_str
    assert "Log File Analyzer" in html_str
    assert "Parse Health" in html_str
    assert 'id="findingsTable"' in html_str

    # Verify raw <script> payload in log input is HTML-escaped and never injected unescaped
    xss_line = (
        '198.51.100.88 - - [25/Nov/2026:10:01:25 +0000] '
        '"GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
    )
    from log_analyzer.parsers import parse_log_lines

    xss_result = engine.analyze(parse_log_lines([xss_line], log_format="nginx"), detected_format="nginx")
    xss_html = format_html(xss_result)
    assert "<script>alert(1)</script>" not in xss_html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in xss_html

    html_path = export_html(result, tmp_path / "report.html")
    assert html_path.is_file()
    assert html_path.read_text(encoding="utf-8") == html_str


def test_should_show_progress_logic() -> None:
    small = PROGRESS_THRESHOLD_BYTES - 1
    large = PROGRESS_THRESHOLD_BYTES + 1

    assert should_show_progress(small, "terminal", None, is_tty=True) is False
    assert should_show_progress(large, "terminal", None, is_tty=True) is True
    assert should_show_progress(large, "terminal", None, is_tty=False) is False
    assert should_show_progress(large, "json", None, is_tty=True) is False
    assert should_show_progress(large, "csv", None, is_tty=True) is False
    assert should_show_progress(large, "html", None, is_tty=True) is False
    assert should_show_progress(large, "json", "out.json", is_tty=True) is True
    assert should_show_progress(large, "html", "out.html", is_tty=True) is True


def test_cli_exit_codes_and_all_output_modes(tmp_path: Path, capsys) -> None:
    # 1. Clean log file -> exit code 0
    clean_log = tmp_path / "clean.log"
    clean_log.write_text(
        '10.0.1.15 - - [25/Nov/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )
    assert cli_main(["--input", str(clean_log), "--output", "json"]) == EXIT_CLEAN
    clean_data = json.loads(capsys.readouterr().out)
    assert clean_data["summary"]["total_findings"] == 0

    # 2. access.log with threats -> exit code 1 + JSON output
    assert cli_main(["--input", str(SAMPLE_ACCESS_LOG), "--output", "json"]) == EXIT_THREATS_FOUND
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["detected_format"] == "nginx"
    found_ids = {f["rule_id"] for f in data["findings"]}
    assert {"WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-005", "BEH-001", "BEH-002", "BEH-003"}.issubset(
        found_ids
    )
    # Verify deduplication grouped the 10 gobuster hits from 198.51.100.42 into 1 finding
    gobuster_findings = [
        f for f in data["findings"] if f["rule_id"] == "WEB-005" and f["source_ip"] == "198.51.100.42"
    ]
    assert len(gobuster_findings) == 1
    assert gobuster_findings[0]["hit_count"] == 10

    # 3. auth.log -> CSV file export filtered to HIGH+ (exit code 1)
    csv_out = tmp_path / "auth_high.csv"
    assert (
        cli_main(
            [
                "--input",
                str(SAMPLE_AUTH_LOG),
                "--format",
                "auto",
                "--output",
                "csv",
                "--output-file",
                str(csv_out),
                "--min-severity",
                "HIGH",
            ]
        )
        == EXIT_THREATS_FOUND
    )
    rows = list(csv.DictReader(csv_out.open("r", encoding="utf-8")))
    assert len(rows) > 0
    assert all(Severity.from_str(r["severity"]) >= Severity.HIGH for r in rows)

    # 4. HTML file export on gzip-compressed access log (exit code 1)
    gz_log = tmp_path / "access.log.gz"
    with gzip.open(gz_log, "wt", encoding="utf-8") as fh:
        fh.write(SAMPLE_ACCESS_LOG.read_text(encoding="utf-8"))
    html_out = tmp_path / "report.html"
    assert (
        cli_main(["--input", str(gz_log), "--output", "html", "--output-file", str(html_out)])
        == EXIT_THREATS_FOUND
    )
    assert html_out.is_file()
    assert "<!DOCTYPE html>" in html_out.read_text(encoding="utf-8")

    # 5. Missing input file -> exit code 2
    assert cli_main(["--input", str(tmp_path / "missing.log")]) == EXIT_ERROR

    # 6. Malformed rules file -> exit code 2
    bad_rules = tmp_path / "bad.yaml"
    bad_rules.write_text("signatures:\n  - id: X\n    name: X\n    severity: HIGH\n    patterns: ['[']\n", encoding="utf-8")
    assert cli_main(["--input", str(clean_log), "--rules", str(bad_rules)]) == EXIT_ERROR
