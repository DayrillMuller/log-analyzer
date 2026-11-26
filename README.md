# Log File Analyzer

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/DayrillMuller/log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/DayrillMuller/log-analyzer/actions/workflows/ci.yml)

A fast, memory-safe Python CLI tool that streams multi-format server and application logs (`.log`, `.gz`, `.zip`), detects web/system attacks and behavioral anomalies, deduplicates noisy alerts, and generates structured threat reports.

---

## Key Features

- **Streaming & Compressed Parsing:** O(1)-memory generator parsers with automatic format detection for `nginx` (Nginx/Apache Combined & Common), `auth` (Linux SSH/PAM/`sudo`), `syslog` (RFC 3164, RFC 5424, ISO-8601), and `generic` (structured app logs & JSON Lines) — transparently reading plain text, `.gz`, and `.zip` archives.
- **Two-Layer Threat Detection:**
  - **Pre-Compiled Regex Signatures:** Detects SQL Injection, XSS, Path Traversal/LFI, OS Command Injection (with URL decoding), scanner User-Agents (`sqlmap`, `nikto`, `gobuster`), root login attempts, `sudo` privilege escalation failures, invalid user enumeration, account lockouts, and kernel/service crashes.
  - **TTL-Bounded Sliding-Window Anomalies:** Detects per-IP brute-force bursts (`401`/`403` and SSH auth failures), `404` directory enumeration bursts, and traffic spikes / DoS indicators while periodically evicting expired timestamps and inactive IPs so memory remains flat on multi-gigabyte logs.
- **Low-Noise Alerting:**
  - **Smart Alert Deduplication:** Consolidates repeated triggers of the same `(rule_id, source_ip)` within a configurable cooldown window into a single summary `Finding` (`hit_count`, `first_seen`, `last_seen`, and up to 3 sample evidence lines).
  - **Allowlist Exclusions:** Suppresses false positives from trusted IPs/CIDR blocks (e.g., `127.0.0.1/32`), exact safe paths (`/healthz`, `/favicon.ico`), and benign User-Agents (`kube-probe/`).
- **Resilient & CI/CD-Ready:** Handles encoding corruption (`errors="replace"`), normalizes mixed timezones to UTC, reports **Parse Health** (`parsed` / `malformed` / `blank`), displays a `rich` progress bar on files > 5 MB, and returns standardized exit codes (`0` clean, `1` threats detected, `2` error).
- **Multi-Format Reports:** Color-coded `rich` terminal dashboards, machine-readable `json` and `csv`, and a self-contained dark-mode interactive `html` report with clickable severity cards and live filtering.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/DayrillMuller/log-analyzer.git
cd log-analyzer

# 2. Install in editable mode (registers the `log-analyzer` CLI command)
pip install -e .

# 3. Run against the included synthetic sample logs
log-analyzer --input sample_logs/access.log
log-analyzer --input sample_logs/auth.log --min-severity HIGH

# 4. Export structured JSON, CSV, or self-contained dark-mode HTML reports
log-analyzer --input sample_logs/access.log --output json --output-file report.json
log-analyzer --input sample_logs/auth.log --output csv --output-file findings.csv
log-analyzer --input sample_logs/access.log --output html --output-file report.html

# 5. Analyze compressed archives directly (.gz or .zip)
log-analyzer --input /var/log/nginx/access.log.1.gz --min-severity MEDIUM
```

### CLI Options & Exit Codes

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--input` | `-i` | *(required)* | Path to plain-text, `.gz`, or `.zip` log file |
| `--format` | `-f` | `auto` | Log format: `auto`, `nginx`, `auth`, `syslog`, `generic` |
| `--rules` | `-r` | built-in `rules.yaml` | Path to a custom YAML rules file |
| `--output` | `-o` | `terminal` | Output format: `terminal`, `json`, `csv`, `html` |
| `--output-file` | `-O` | stdout | Destination file path for `json`/`csv`/`html` reports |
| `--min-severity` | `-s` | `LOW` | Minimum severity to report: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--version` | `-V` | — | Display version and exit |

**Exit Codes:** `0` = no findings at or above `--min-severity` | `1` = threats detected | `2` = invalid arguments, missing/corrupt file, or malformed rules.

---

## Example Terminal Output

```text
┌──────────────── Log File Analyzer - Threat Report ────────────────┐
│        Input Source:  sample_logs\access.log                      │
│          Log Format:  nginx                                       │
│        Parse Health:  64 parsed / 64 total (0 malformed, 0 blank) │
│  Allowlisted Events:  1                                           │
│   Unique Source IPs:  11                                          │
│ Min Severity Filter:  LOW                                         │
│      Total Findings:  9 alerts (68 total hits)                    │
│       Scan Duration:  0.015s                                      │
└───────────────────────────────────────────────────────────────────┘
    Severity Breakdown
┌──────────────┬──────────┐
│   Severity   │   Alerts │
├──────────────┼──────────┤
│   CRITICAL   │        2 │
│     HIGH     │        4 │
│    MEDIUM    │        3 │
│      LOW     │        0 │
└──────────────┴──────────┘
                                   Detailed Security Findings
┌────────────┬──────┬─────────────────┬──────────────────────┬──────────────────────────────────┐
│  Severity  │ Hits │ Rule            │ Source / Window      │ Evidence                         │
├────────────┼──────┼─────────────────┼──────────────────────┼──────────────────────────────────┤
│  CRITICAL  │   2x │ WEB-001         │ 198.51.100.77        │ 2 occurrences (lines 6, 7);      │
│            │      │ SQL Injection   │ 10:01:02Z->10:01:05Z │ matched "UNION SELECT", "' OR 1=1"│
├────────────┼──────┼─────────────────┼──────────────────────┼──────────────────────────────────┤
│  CRITICAL  │   2x │ WEB-004         │ 203.0.113.19         │ 2 occurrences (lines 11, 12);    │
│            │      │ Command Inject. │ 10:01:46Z->10:01:51Z │ matched ";cat", "|whoami"        │
├────────────┼──────┼─────────────────┼──────────────────────┼──────────────────────────────────┤
│    HIGH    │   7x │ BEH-001         │ 203.0.113.55         │ 7 events in 18s (threshold 5/60s)│
│            │      │ Brute-Force     │ 10:02:10Z->10:02:28Z │ lines 14-20; POST /api/v1/auth   │
├────────────┼──────┼─────────────────┼──────────────────────┼──────────────────────────────────┤
│   MEDIUM   │  10x │ WEB-005         │ 198.51.100.42        │ 10 occurrences (lines 21-30);    │
│            │      │ Scanner UA      │ 10:03:01Z->10:03:19Z │ matched "gobuster" (3 samples)   │
└────────────┴──────┴─────────────────┴──────────────────────┴──────────────────────────────────┘
```

---

## Customizing Detection Rules

All detection rules, sliding-window thresholds, deduplication settings, and allowlists are externalized in [`log_analyzer/rules.yaml`](log_analyzer/rules.yaml) (or pass a custom file with `--rules custom_rules.yaml`):

```yaml
allowlist:
  ips_and_cidrs:
    - "127.0.0.1/32"
    - "10.250.0.0/16"      # Trusted internal vulnerability scanner subnet
  paths:
    - "/healthz"
    - "/favicon.ico"
  user_agents:
    - "^kube-probe/"

deduplication:
  enabled: true
  cooldown_seconds: 300    # Group repeated alerts per (rule_id, source_ip)
  max_samples: 3

signatures:
  - id: CUSTOM-001
    name: Exposed API Key in Query String
    category: data_exposure
    severity: HIGH
    formats: [nginx, generic]
    url_decode: true
    fields: [endpoint_or_service, message]
    patterns:
      - 'api_key=[A-Za-z0-9_-]{24,}'
    remediation_hint: "Revoke the exposed credential and move tokens out of URL query parameters."

behavioral_rules:
  - id: BEH-CUSTOM
    name: Upstream 5xx Error Spike
    category: availability
    severity: MEDIUM
    threshold: 10
    window_seconds: 60
    match:
      status_codes: [500, 502, 503]
    remediation_hint: "Inspect backend service health and recent deployments."
```

---

## Project Structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml           # GitHub Actions CI matrix (Python 3.10, 3.11, 3.12)
├── log_analyzer/
│   ├── __init__.py          # Public package exports
│   ├── __main__.py          # `python -m log_analyzer` entry point
│   ├── cli.py               # CLI flags, progress bar, and standardized exit codes
│   ├── parsers.py           # Streaming parsers (.log/.gz/.zip), auto-detect, ParseStats
│   ├── rules.yaml           # Signatures, behavioral thresholds, allowlist, deduplication
│   ├── detector.py          # DetectionEngine, TTL-bounded windows, Finding/Severity models
│   └── reporter.py          # Rich terminal, JSON, CSV, and dark-mode HTML exporters
├── sample_logs/
│   ├── access.log           # Synthetic Nginx log with benign + simulated attack traffic
│   └── auth.log             # Synthetic Linux auth/syslog with benign + attack scenarios
├── tests/
│   ├── test_parsers.py
│   ├── test_detector.py
│   └── test_reporter_and_cli.py
├── CHANGELOG.md
├── LICENSE
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Development & Testing

```bash
pip install -e ".[dev]"
pytest -v
```

## License

Released under the [MIT License](LICENSE).
