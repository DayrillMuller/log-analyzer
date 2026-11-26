"""Command-line interface for the Log File Analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from log_analyzer.detector import DetectionEngine, Severity, load_rules
from log_analyzer.parsers import (
    SUPPORTED_FORMATS,
    ParseStats,
    detect_log_format,
    get_stream_total_bytes,
    parse_log_file,
)
from log_analyzer.reporter import (
    export_csv,
    export_html,
    export_json,
    format_csv,
    format_html,
    format_json,
    render_terminal_report,
)

__version__ = "1.0.0"

EXIT_CLEAN = 0
EXIT_THREATS_FOUND = 1
EXIT_ERROR = 2

PROGRESS_THRESHOLD_BYTES = 5 * 1024 * 1024  # 5 MB
OUTPUT_FORMATS: tuple[str, ...] = ("terminal", "json", "csv", "html")


def should_show_progress(
    file_size_bytes: int,
    output_format: str,
    output_file: Optional[str],
    is_tty: bool,
) -> bool:
    """Determine whether to display the Rich progress bar.

    Enabled only for files > 5 MB on interactive terminals when not streaming raw
    machine-readable output directly to stdout.
    """
    if file_size_bytes <= PROGRESS_THRESHOLD_BYTES:
        return False
    if not is_tty:
        return False
    if output_format in ("json", "csv", "html") and output_file is None:
        return False
    return True


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description=(
            "Parse multi-format server/application logs (.log, .gz, .zip), detect suspicious "
            "patterns and behavioral anomalies, and generate structured threat reports."
        ),
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to the log file or compressed archive (.gz, .zip) to analyze.",
    )
    parser.add_argument(
        "--format",
        "-f",
        dest="log_format",
        choices=SUPPORTED_FORMATS,
        default="auto",
        help="Log format parser to use (default: auto).",
    )
    parser.add_argument(
        "--rules",
        "-r",
        default=None,
        help="Path to custom YAML rules file (default: built-in rules.yaml).",
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=OUTPUT_FORMATS,
        default="terminal",
        help="Report output format (default: terminal).",
    )
    parser.add_argument(
        "--output-file",
        "-O",
        default=None,
        help="Optional destination file path for json/csv/html reports (prints to stdout if omitted).",
    )
    parser.add_argument(
        "--min-severity",
        "-s",
        default="LOW",
        type=lambda value: value.upper(),
        choices=("LOW", "MEDIUM", "HIGH", "CRITICAL"),
        help="Minimum severity level to include in the report (default: LOW).",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the Log File Analyzer CLI.

    Exit codes:
      0 - Analysis completed with no findings meeting --min-severity
      1 - Analysis completed and one or more threats were detected
      2 - Invalid arguments, missing/corrupt input file, or configuration error
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Error: Input log file not found: {input_path}", file=sys.stderr)
        return EXIT_ERROR

    try:
        rules = load_rules(args.rules)
        min_severity = Severity.from_str(args.min_severity)
        detected_format = (
            detect_log_format(input_path)
            if args.log_format == "auto"
            else args.log_format
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    parse_stats = ParseStats()
    engine = DetectionEngine(rules=rules)

    file_size = input_path.stat().st_size
    is_tty = bool(getattr(sys.stderr, "isatty", lambda: False)()) and bool(
        getattr(sys.stdout, "isatty", lambda: False)()
    )
    use_progress = should_show_progress(
        file_size_bytes=file_size,
        output_format=args.output,
        output_file=args.output_file,
        is_tty=is_tty,
    )

    try:
        if use_progress:
            total_bytes = get_stream_total_bytes(input_path)
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Analyzing {task.fields[filename]}"),
                BarColumn(),
                TaskProgressColumn(),
                DownloadColumn(),
                TextColumn("[dim]{task.fields[lines]:,} lines"),
                TimeElapsedColumn(),
                console=Console(stderr=True),
                transient=True,
            ) as progress:
                task_id = progress.add_task(
                    "scan",
                    total=total_bytes or None,
                    filename=input_path.name,
                    lines=0,
                )
                lines_seen = 0

                def _on_progress(bytes_delta: int, lines_delta: int) -> None:
                    nonlocal lines_seen
                    lines_seen += lines_delta
                    if bytes_delta > 0 or lines_seen % 500 == 0:
                        progress.update(task_id, advance=bytes_delta, lines=lines_seen)

                entries = parse_log_file(
                    input_path,
                    log_format=detected_format,
                    stats=parse_stats,
                    progress_callback=_on_progress,
                )
                result = engine.analyze(
                    entries,
                    input_source=str(input_path),
                    detected_format=detected_format,
                    min_severity=min_severity,
                    parse_stats=parse_stats,
                )
                progress.update(task_id, completed=total_bytes or None, lines=lines_seen)
        else:
            entries = parse_log_file(
                input_path,
                log_format=detected_format,
                stats=parse_stats,
            )
            result = engine.analyze(
                entries,
                input_source=str(input_path),
                detected_format=detected_format,
                min_severity=min_severity,
                parse_stats=parse_stats,
            )
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"Error analyzing '{input_path}': {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        if args.output == "terminal":
            console = Console(force_terminal=None)
            render_terminal_report(result, console=console)
        elif args.output == "json":
            if args.output_file:
                written = export_json(result, args.output_file)
                print(f"JSON report written to {written}", file=sys.stderr)
            else:
                print(format_json(result))
        elif args.output == "csv":
            if args.output_file:
                written = export_csv(result, args.output_file)
                print(f"CSV report written to {written}", file=sys.stderr)
            else:
                print(format_csv(result), end="")
        elif args.output == "html":
            if args.output_file:
                written = export_html(result, args.output_file)
                print(f"HTML report written to {written}", file=sys.stderr)
            else:
                print(format_html(result))
    except OSError as exc:
        print(f"Error writing output report: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_THREATS_FOUND if result.findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
