"""Log File Analyzer - Multi-format log parsing, threat detection, and reporting."""

from __future__ import annotations

from log_analyzer.detector import (
    AllowlistConfig,
    AnalysisResult,
    BehavioralRule,
    DeduplicationConfig,
    DetectionEngine,
    Finding,
    RuleSet,
    Severity,
    SignatureRule,
    load_rules,
)
from log_analyzer.parsers import (
    SUPPORTED_FORMATS,
    LogEntry,
    ParseStats,
    detect_log_format,
    get_stream_total_bytes,
    parse_flexible_timestamp,
    parse_log_file,
    parse_log_lines,
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

__all__ = [
    "__version__",
    "AllowlistConfig",
    "AnalysisResult",
    "BehavioralRule",
    "DeduplicationConfig",
    "DetectionEngine",
    "Finding",
    "LogEntry",
    "ParseStats",
    "RuleSet",
    "SUPPORTED_FORMATS",
    "Severity",
    "SignatureRule",
    "detect_log_format",
    "export_csv",
    "export_html",
    "export_json",
    "format_csv",
    "format_html",
    "format_json",
    "get_stream_total_bytes",
    "load_rules",
    "parse_flexible_timestamp",
    "parse_log_file",
    "parse_log_lines",
    "render_terminal_report",
]
