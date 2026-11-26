# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-26

### Added
- **Streaming Multi-Format Parsers (`log_analyzer/parsers.py`)**: Memory-efficient generator parsers with automatic format detection for `nginx`, `auth`, `syslog` (RFC 3164, RFC 5424, ISO-8601), and `generic` (structured app logs and JSON Lines), plus transparent `.gz` and `.zip` decompression.
- **Fault Tolerance & Parse Health**: Graceful handling of encoding errors (`errors="replace"`), mixed timezones normalized to UTC, and malformed line tracking (`ParseStats`) reported in every output format.
- **Two-Layer Threat Detection (`log_analyzer/detector.py` & `log_analyzer/rules.yaml`)**:
  - Pre-compiled and validated regex signatures for SQL Injection, XSS, Path Traversal/LFI, OS Command Injection (with URL decoding), security scanner User-Agents, root login attempts, `sudo` privilege escalation failures, invalid user enumeration, account lockouts, and critical service crashes.
  - TTL-bounded stateful sliding-window anomaly detection for per-IP brute-force bursts, `404` directory enumeration, and traffic spikes / DoS indicators with periodic inactive-IP eviction and hard memory caps.
- **Noise Reduction**: Configurable IP/CIDR, exact safe path, and User-Agent `allowlist`, plus smart alert deduplication grouping repeated `(rule_id, source_ip)` triggers within a cooldown window into summary findings (`hit_count`, `first_seen`, `last_seen`, and up to 3 sample evidence lines).
- **Multi-Format Reporting & CLI (`log_analyzer/reporter.py` & `log_analyzer/cli.py`)**:
  - Rich terminal dashboard, JSON export, CSV export, and self-contained dark-mode interactive HTML report (`--output html`) with XSS-safe escaping.
  - Automatic `rich` progress bar for files larger than 5 MB (auto-disabled when piping or streaming machine-readable stdout).
  - Standardized automation exit codes: `0` (clean), `1` (threats detected), `2` (CLI/file/config errors).
- **Packaging, Samples & Tests**: `pyproject.toml` with `log-analyzer` CLI entry point, synthetic `sample_logs/` (`access.log` and `auth.log`), GitHub Actions CI workflow, and a 38-test `pytest` suite.
