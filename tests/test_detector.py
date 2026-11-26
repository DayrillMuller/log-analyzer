"""Unit tests for signatures, allowlisting, deduplication, and TTL-bounded sliding windows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from log_analyzer.detector import DetectionEngine, Severity, load_rules
from log_analyzer.parsers import LogEntry, parse_log_lines


def _make_entry(
    *,
    ts_offset_sec: int = 0,
    source_ip: str | None = "203.0.113.10",
    level: str = "INFO",
    endpoint_or_service: str | None = "GET /",
    status_code: int | None = 200,
    message: str = "normal request",
    line_number: int = 1,
    user_agent: str | None = None,
    request_path: str | None = None,
) -> LogEntry:
    base_ts = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)
    return LogEntry(
        timestamp=base_ts + timedelta(seconds=ts_offset_sec),
        source_ip=source_ip,
        level=level,
        endpoint_or_service=endpoint_or_service,
        status_code=status_code,
        message=message,
        raw_line=message,
        line_number=line_number,
        user_agent=user_agent,
        request_path=request_path,
    )


def test_benign_traffic_produces_no_findings() -> None:
    nginx_lines = [
        '10.0.1.15 - - [25/Nov/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0"',
        '10.0.1.15 - - [25/Nov/2026:10:00:05 +0000] "GET /products/order-123 HTTP/1.1" 200 1200 "-" "Mozilla/5.0"',
        '10.0.1.22 - - [25/Nov/2026:10:00:08 +0000] "POST /api/v1/cart HTTP/1.1" 201 256 "-" "Mozilla/5.0"',
    ]
    auth_lines = [
        "Nov 25 09:58:02 prod-bastion-01 sshd[10211]: Accepted publickey for deploy from 10.0.2.10 port 51422 ssh2",
        "Nov 25 09:58:15 prod-bastion-01 sudo[10248]:   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
    ]
    engine = DetectionEngine()
    nginx_result = engine.analyze(parse_log_lines(nginx_lines, log_format="nginx"), detected_format="nginx")
    assert nginx_result.total_lines == 3
    assert nginx_result.findings == []

    auth_result = engine.analyze(
        parse_log_lines(auth_lines, log_format="auth", default_year=2026),
        detected_format="auth",
    )
    assert auth_result.total_lines == 2
    assert auth_result.findings == []


@pytest.mark.parametrize(
    ("raw_line", "expected_rule_id"),
    [
        (
            '198.51.100.1 - - [25/Nov/2026:10:00:01 +0000] "GET /items?id=1%27%20UNION%20SELECT%201,2-- HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
            "WEB-001",
        ),
        (
            '198.51.100.1 - - [25/Nov/2026:10:00:01 +0000] "GET /login?u=admin\' OR 1=1-- HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
            "WEB-001",
        ),
        (
            '198.51.100.2 - - [25/Nov/2026:10:00:02 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
            "WEB-002",
        ),
        (
            '198.51.100.3 - - [25/Nov/2026:10:00:03 +0000] "GET /files?p=../../../etc/passwd HTTP/1.1" 400 10 "-" "curl/8.0"',
            "WEB-003",
        ),
        (
            '198.51.100.4 - - [25/Nov/2026:10:00:04 +0000] "GET /ping?h=1.1.1.1;cat%20/etc/hosts HTTP/1.1" 500 10 "-" "curl/8.0"',
            "WEB-004",
        ),
        (
            '198.51.100.5 - - [25/Nov/2026:10:00:05 +0000] "GET /ping?h=1.1.1.1|whoami HTTP/1.1" 500 10 "-" "curl/8.0"',
            "WEB-004",
        ),
        (
            '198.51.100.6 - - [25/Nov/2026:10:00:06 +0000] "GET / HTTP/1.1" 200 10 "-" "Nikto/2.5.0"',
            "WEB-005",
        ),
    ],
)
def test_web_attack_signatures(raw_line: str, expected_rule_id: str) -> None:
    engine = DetectionEngine()
    result = engine.analyze(parse_log_lines([raw_line], log_format="nginx"), detected_format="nginx")
    rule_ids = {f.rule_id for f in result.findings}
    assert expected_rule_id in rule_ids


@pytest.mark.parametrize(
    ("raw_line", "expected_rule_id"),
    [
        (
            "Nov 25 10:02:10 host sshd[101]: Failed password for root from 198.51.100.14 port 60101 ssh2",
            "AUTH-001",
        ),
        (
            "Nov 25 10:03:42 host sudo[106]: intern : user NOT in sudoers ; TTY=pts/2 ; USER=root ; COMMAND=/usr/sbin/visudo",
            "AUTH-002",
        ),
        (
            "Nov 25 10:01:04 host sshd[104]: Invalid user oracle from 203.0.113.200 port 49188",
            "AUTH-003",
        ),
        (
            "Nov 25 10:05:18 host kernel: [84215.10] nginx[4812]: segfault at 0000000000000018 error 4",
            "SYS-001",
        ),
        (
            "Nov 25 10:02:25 host sshd[105]: Disconnecting authenticating user root 198.51.100.14: Too many authentication failures",
            "SYS-002",
        ),
    ],
)
def test_auth_and_system_signatures(raw_line: str, expected_rule_id: str) -> None:
    engine = DetectionEngine()
    result = engine.analyze(
        parse_log_lines([raw_line], log_format="auth", default_year=2026),
        detected_format="auth",
    )
    rule_ids = {f.rule_id for f in result.findings}
    assert expected_rule_id in rule_ids


def test_allowlist_cidr_path_and_user_agent_exclusions(tmp_path: Path) -> None:
    rules_file = tmp_path / "allowlist_rules.yaml"
    rules_file.write_text(
        """
allowlist:
  ips_and_cidrs:
    - "10.250.0.0/16"
    - "127.0.0.1/32"
  paths:
    - "/healthz"
    - "/favicon.ico"
  user_agents:
    - "^InternalMonitor/"
signatures:
  - id: WEB-001
    name: SQLi
    severity: CRITICAL
    fields: [endpoint_or_service, message]
    patterns: ['UNION\\s+SELECT']
    remediation_hint: "Block IP"
  - id: WEB-005
    name: Scanner
    severity: MEDIUM
    fields: [message]
    patterns: ['sqlmap']
    remediation_hint: "Block scanner"
behavioral_rules:
  - id: BEH-002
    name: 404 Burst
    severity: MEDIUM
    threshold: 3
    window_seconds: 60
    match:
      status_codes: [404]
    remediation_hint: "Throttle IP"
""",
        encoding="utf-8",
    )
    rules = load_rules(rules_file)
    engine = DetectionEngine(rules=rules)

    lines = [
        # 1. Trusted CIDR internal scanner -> must be excluded
        '10.250.12.5 - - [25/Nov/2026:10:00:01 +0000] "GET /api?id=1 UNION SELECT 1-- HTTP/1.1" 200 10 "-" "sqlmap/1.7"',
        # 2. Exact safe path /favicon.ico 404s -> must be excluded (even repeated)
        '198.51.100.50 - - [25/Nov/2026:10:00:02 +0000] "GET /favicon.ico HTTP/1.1" 404 10 "-" "Mozilla/5.0"',
        '198.51.100.50 - - [25/Nov/2026:10:00:03 +0000] "GET /favicon.ico HTTP/1.1" 404 10 "-" "Mozilla/5.0"',
        '198.51.100.50 - - [25/Nov/2026:10:00:04 +0000] "GET /favicon.ico HTTP/1.1" 404 10 "-" "Mozilla/5.0"',
        # 3. Trusted User-Agent -> must be excluded
        '198.51.100.51 - - [25/Nov/2026:10:00:05 +0000] "GET /api?id=1 UNION SELECT 1-- HTTP/1.1" 200 10 "-" "InternalMonitor/2.1"',
        # 4. Safe path WITH malicious query string -> must NOT bypass detection!
        '198.51.100.99 - - [25/Nov/2026:10:00:06 +0000] "GET /healthz?id=1 UNION SELECT password FROM users HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    ]
    result = engine.analyze(parse_log_lines(lines, log_format="nginx"), detected_format="nginx")
    assert result.allowlisted_count == 5
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "WEB-001"
    assert result.findings[0].source_ip == "198.51.100.99"


def test_alert_deduplication_aggregates_noisy_scans_and_respects_cooldown() -> None:
    # 10 gobuster hits within 18 seconds -> 1 aggregated WEB-005 finding with hit_count=10 and 3 samples
    burst_1 = [
        f'198.51.100.42 - - [25/Nov/2026:10:00:{i * 2:02d} +0000] "GET /probe-{i} HTTP/1.1" 200 10 "-" "gobuster/3.6"'
        for i in range(10)
    ]
    # 2 more hits 10 minutes later (> 300s default cooldown) -> separate 2nd aggregated finding
    burst_2 = [
        '198.51.100.42 - - [25/Nov/2026:10:10:00 +0000] "GET /late-1 HTTP/1.1" 200 10 "-" "gobuster/3.6"',
        '198.51.100.42 - - [25/Nov/2026:10:10:05 +0000] "GET /late-2 HTTP/1.1" 200 10 "-" "gobuster/3.6"',
    ]

    engine = DetectionEngine()
    result = engine.analyze(parse_log_lines(burst_1 + burst_2, log_format="nginx"), detected_format="nginx")
    scanner_findings = [f for f in result.findings if f.rule_id == "WEB-005"]
    assert len(scanner_findings) == 2

    first_group = scanner_findings[0]
    assert first_group.hit_count == 10
    assert first_group.first_seen == "2026-11-25T10:00:00Z"
    assert first_group.last_seen == "2026-11-25T10:00:18Z"
    assert len(first_group.sample_evidence) == 3
    assert len(first_group.line_numbers) == 10

    second_group = scanner_findings[1]
    assert second_group.hit_count == 2
    assert second_group.first_seen == "2026-11-25T10:10:00Z"
    assert second_group.last_seen == "2026-11-25T10:10:05Z"
    assert len(second_group.sample_evidence) == 2


def test_brute_force_sliding_window_triggers_and_consolidates() -> None:
    entries = [
        _make_entry(
            ts_offset_sec=i * 3,
            source_ip="203.0.113.55",
            endpoint_or_service="POST /api/login",
            status_code=401,
            message="POST /api/login status=401",
            line_number=i + 1,
        )
        for i in range(7)
    ]
    engine = DetectionEngine()
    result = engine.analyze(entries)
    beh_findings = [f for f in result.findings if f.rule_id == "BEH-001"]
    assert len(beh_findings) == 1
    finding = beh_findings[0]
    assert finding.source_ip == "203.0.113.55"
    assert finding.hit_count == 7
    assert finding.event_count == 7
    assert finding.line_numbers == [1, 2, 3, 4, 5, 6, 7]
    assert "->" in (finding.timestamp or "")
    assert "7 events" in finding.evidence


def test_sliding_window_respects_time_expiry_and_ip_isolation() -> None:
    spread_entries = [
        _make_entry(ts_offset_sec=0, source_ip="198.51.100.90", status_code=401, line_number=1),
        _make_entry(ts_offset_sec=4, source_ip="198.51.100.90", status_code=401, line_number=2),
        _make_entry(ts_offset_sec=8, source_ip="198.51.100.90", status_code=401, line_number=3),
        _make_entry(ts_offset_sec=12, source_ip="198.51.100.90", status_code=401, line_number=4),
        _make_entry(ts_offset_sec=90, source_ip="198.51.100.90", status_code=401, line_number=5),
        _make_entry(ts_offset_sec=1, source_ip="198.51.100.91", status_code=401, line_number=6),
        _make_entry(ts_offset_sec=2, source_ip="198.51.100.91", status_code=401, line_number=7),
        _make_entry(ts_offset_sec=3, source_ip="198.51.100.91", status_code=401, line_number=8),
        _make_entry(ts_offset_sec=4, source_ip="198.51.100.91", status_code=401, line_number=9),
    ]
    engine = DetectionEngine()
    result = engine.analyze(spread_entries)
    assert [f for f in result.findings if f.rule_id == "BEH-001"] == []


def test_separate_bursts_emit_distinct_findings() -> None:
    entries = [
        _make_entry(ts_offset_sec=i * 2, source_ip="203.0.113.77", status_code=401, line_number=i + 1)
        for i in range(5)
    ] + [
        _make_entry(ts_offset_sec=130 + i * 2, source_ip="203.0.113.77", status_code=401, line_number=i + 10)
        for i in range(5)
    ]
    engine = DetectionEngine()
    result = engine.analyze(entries)
    beh_findings = [f for f in result.findings if f.rule_id == "BEH-001"]
    assert len(beh_findings) == 2


def test_sliding_window_ttl_cleanup_and_hard_memory_cap() -> None:
    # 1. Verify periodic TTL eviction removes expired inactive IPs from memory
    engine = DetectionEngine(cleanup_interval=50, max_tracked_ips=1000)
    for idx in range(120):
        engine.process_entry(
            _make_entry(
                ts_offset_sec=0,
                source_ip=f"198.51.{idx // 250}.{idx % 250 + 1}",
                status_code=404,
                line_number=idx + 1,
            ),
            log_format="nginx",
        )
    # All 120 IPs have active windows (for BEH-002 and BEH-003)
    assert engine.tracked_window_count >= 120

    # Advance time well beyond the 60s window and invoke cleanup
    later_ts = datetime(2026, 11, 25, 10, 5, 0, tzinfo=timezone.utc)
    engine.cleanup_expired_state(reference_time=later_ts)
    assert engine.tracked_window_count == 0

    # 2. Verify hard memory cap prevents unbounded growth under spoofed-IP flood within same second
    capped_engine = DetectionEngine(cleanup_interval=10, max_tracked_ips=25)
    for idx in range(100):
        capped_engine.process_entry(
            _make_entry(
                ts_offset_sec=0,
                source_ip=f"203.0.113.{idx + 1}",
                status_code=200,
                line_number=idx + 1,
            ),
            log_format="nginx",
        )
    assert capped_engine.tracked_window_count <= 25


def test_directory_enumeration_and_dos_spike_behavioral_rules() -> None:
    enum_entries = [
        _make_entry(
            ts_offset_sec=i * 2,
            source_ip="198.51.100.42",
            endpoint_or_service=f"GET /probe-{i}",
            status_code=404,
            line_number=i + 1,
        )
        for i in range(9)
    ]
    dos_entries = [
        _make_entry(
            ts_offset_sec=i,
            source_ip="192.0.2.99",
            endpoint_or_service="GET /api/catalog",
            status_code=200,
            line_number=100 + i,
        )
        for i in range(32)
    ]
    engine = DetectionEngine()
    result = engine.analyze(enum_entries + dos_entries)
    ids_by_ip = {(f.rule_id, f.source_ip) for f in result.findings}
    assert ("BEH-002", "198.51.100.42") in ids_by_ip
    assert ("BEH-003", "192.0.2.99") in ids_by_ip


def test_regex_and_cidr_validation_errors(tmp_path: Path) -> None:
    bad_regex_yaml = tmp_path / "bad_regex.yaml"
    bad_regex_yaml.write_text(
        """
signatures:
  - id: BAD-001
    name: Broken Regex
    severity: HIGH
    patterns:
      - '[unclosed_bracket'
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Malformed regex in signature rule 'BAD-001'"):
        load_rules(bad_regex_yaml)

    bad_cidr_yaml = tmp_path / "bad_cidr.yaml"
    bad_cidr_yaml.write_text(
        """
allowlist:
  ips_and_cidrs:
    - "999.999.999.999/32"
signatures: []
behavioral_rules: []
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid IP/CIDR"):
        load_rules(bad_cidr_yaml)


def test_min_severity_filtering_and_custom_rules(tmp_path: Path) -> None:
    custom_yaml = tmp_path / "custom_rules.yaml"
    custom_yaml.write_text(
        """
signatures:
  - id: CUST-LOW
    name: Custom Low Rule
    severity: LOW
    fields: [message]
    patterns: ['custom_low_token']
    remediation_hint: "Low hint"
  - id: CUST-CRIT
    name: Custom Critical Rule
    severity: CRITICAL
    fields: [message]
    patterns: ['custom_crit_token']
    remediation_hint: "Critical hint"
behavioral_rules: []
""",
        encoding="utf-8",
    )
    rules = load_rules(custom_yaml)
    engine = DetectionEngine(rules=rules)
    entries = [
        _make_entry(message="event with custom_low_token", line_number=1),
        _make_entry(message="event with custom_crit_token", line_number=2),
    ]
    all_res = engine.analyze(entries, min_severity=Severity.LOW)
    assert len(all_res.findings) == 2

    high_res = engine.analyze(entries, min_severity=Severity.HIGH)
    assert len(high_res.findings) == 1
    assert high_res.findings[0].rule_id == "CUST-CRIT"
