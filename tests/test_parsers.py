"""Unit tests for streaming multi-format log parsers, compression, and parse health."""

from __future__ import annotations

import gzip
import types
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from log_analyzer.parsers import (
    LogEntry,
    ParseStats,
    detect_log_format,
    parse_flexible_timestamp,
    parse_log_file,
    parse_log_lines,
)


def test_parse_nginx_combined_line() -> None:
    lines = [
        '192.168.1.50 - alice [25/Nov/2026:10:15:32 +0000] '
        '"GET /api/items?id=42 HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"\n'
    ]
    entries = list(parse_log_lines(lines, log_format="nginx"))
    assert len(entries) == 1
    entry = entries[0]
    assert isinstance(entry, LogEntry)
    assert entry.timestamp == datetime(2026, 11, 25, 10, 15, 32, tzinfo=timezone.utc)
    assert entry.source_ip == "192.168.1.50"
    assert entry.level == "INFO"
    assert entry.endpoint_or_service == "GET /api/items?id=42"
    assert entry.request_path == "/api/items?id=42"
    assert entry.user_agent == "Mozilla/5.0"
    assert entry.status_code == 200
    assert entry.is_malformed is False
    assert entry.line_number == 1


def test_parse_nginx_status_level_mapping() -> None:
    lines = [
        '10.0.0.1 - - [25/Nov/2026:10:00:00 +0000] "GET /ok HTTP/1.1" 200 10 "-" "curl/8.0"',
        '10.0.0.1 - - [25/Nov/2026:10:00:01 +0000] "GET /missing HTTP/1.1" 404 10 "-" "curl/8.0"',
        '10.0.0.1 - - [25/Nov/2026:10:00:02 +0000] "GET /crash HTTP/1.1" 502 10 "-" "curl/8.0"',
    ]
    entries = list(parse_log_lines(lines, log_format="nginx"))
    assert [e.level for e in entries] == ["INFO", "WARNING", "ERROR"]
    assert [e.status_code for e in entries] == [200, 404, 502]


def test_parse_auth_bsd_syslog_line() -> None:
    lines = [
        "Nov 25 10:01:06 bastion sshd[10401]: Failed password for invalid user admin from 203.0.113.200 port 49112 ssh2"
    ]
    entries = list(parse_log_lines(lines, log_format="auth", default_year=2026))
    assert len(entries) == 1
    entry = entries[0]
    assert entry.timestamp == datetime(2026, 11, 25, 10, 1, 6, tzinfo=timezone.utc)
    assert entry.source_ip == "203.0.113.200"
    assert entry.level == "ERROR"
    assert entry.endpoint_or_service == "sshd"
    assert entry.status_code is None
    assert "Failed password" in entry.message


def test_parse_rfc5424_and_iso_syslog() -> None:
    lines = [
        "<131>1 2026-11-25T10:05:00Z web-01 appd 412 ID1 - Connection refused from 198.51.100.9",
        "2026-11-25T10:05:05+00:00 web-01 kernel: nginx[99]: segfault at 0000000000000018",
    ]
    entries = list(parse_log_lines(lines, log_format="syslog"))
    assert len(entries) == 2
    assert entries[0].level == "ERROR"
    assert entries[0].source_ip == "198.51.100.9"
    assert entries[0].endpoint_or_service == "appd"
    assert entries[1].level == "CRITICAL"
    assert entries[1].endpoint_or_service == "kernel"


def test_parse_generic_app_and_json_lines() -> None:
    lines = [
        "2026-11-25 10:15:32,500 [ERROR] billing-api - Request from 10.20.30.40 failed status=500",
        '{"timestamp":"2026-11-25T10:16:00Z","level":"warn","source_ip":"10.20.30.41","service":"auth","status_code":401,"message":"Bad token"}',
        "Completely unstructured line with IP 192.0.2.15 and fatal crash",
    ]
    entries = list(parse_log_lines(lines, log_format="generic"))
    assert len(entries) == 3

    assert entries[0].level == "ERROR"
    assert entries[0].source_ip == "10.20.30.40"
    assert entries[0].status_code == 500
    assert entries[0].endpoint_or_service == "billing-api"

    assert entries[1].level == "WARNING"
    assert entries[1].source_ip == "10.20.30.41"
    assert entries[1].status_code == 401
    assert entries[1].endpoint_or_service == "auth"

    assert entries[2].source_ip == "192.0.2.15"
    assert entries[2].level == "CRITICAL"


def test_mixed_timestamp_timezones_normalize_to_utc() -> None:
    ts_utc = parse_flexible_timestamp("2026-11-25T10:00:00Z")
    ts_plus2 = parse_flexible_timestamp("25/Nov/2026:12:00:00 +0200")
    ts_minus5 = parse_flexible_timestamp("2026-11-25 05:00:00-05:00")
    ts_slash = parse_flexible_timestamp("2026/11/25 10:00:00")

    expected = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)
    assert ts_utc == expected
    assert ts_plus2 == expected
    assert ts_minus5 == expected
    assert ts_slash == expected


def test_auto_format_detection() -> None:
    nginx_sample = [
        '10.0.0.1 - - [25/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
    ]
    auth_sample = [
        "Nov 25 10:01:06 bastion sshd[10401]: Failed password for root from 203.0.113.5 port 22 ssh2"
    ]
    syslog_sample = [
        "Nov 25 10:01:06 app-01 cron[991]: Job backup completed successfully"
    ]
    generic_sample = [
        "2026-11-25 10:01:06 INFO worker - Processed 12 messages"
    ]

    assert detect_log_format(nginx_sample) == "nginx"
    assert detect_log_format(auth_sample) == "auth"
    assert detect_log_format(syslog_sample) == "syslog"
    assert detect_log_format(generic_sample) == "generic"


def test_streaming_generator_and_line_numbers(tmp_path: Path) -> None:
    log_file = tmp_path / "stream.log"
    log_file.write_text(
        '10.0.0.1 - - [25/Nov/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "UA"\n'
        "\n"
        '10.0.0.2 - - [25/Nov/2026:10:00:01 +0000] "GET /b HTTP/1.1" 404 10 "-" "UA"\n',
        encoding="utf-8",
    )
    stats = ParseStats()
    gen = parse_log_file(log_file, log_format="auto", stats=stats)
    assert isinstance(gen, types.GeneratorType)

    entries = list(gen)
    assert len(entries) == 2
    assert entries[0].line_number == 1
    assert entries[1].line_number == 3
    assert entries[1].status_code == 404
    assert stats.total_lines == 3
    assert stats.parsed_lines == 2
    assert stats.blank_lines == 1
    assert stats.malformed_lines == 0


def test_gzip_compressed_log_streaming_and_autodetect(tmp_path: Path) -> None:
    gz_path = tmp_path / "access.log.gz"
    content = (
        '10.0.0.1 - - [25/Nov/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
        '198.51.100.77 - - [25/Nov/2026:10:00:05 +0000] "GET /search?q=1\' OR 1=1-- HTTP/1.1" 200 50 "-" "sqlmap/1.7"\n'
    )
    with gzip.open(gz_path, "wt", encoding="utf-8") as fh:
        fh.write(content)

    assert detect_log_format(gz_path) == "nginx"

    stats = ParseStats()
    gen = parse_log_file(gz_path, log_format="auto", stats=stats)
    assert isinstance(gen, types.GeneratorType)
    entries = list(gen)
    assert len(entries) == 2
    assert entries[1].source_ip == "198.51.100.77"
    assert stats.parsed_lines == 2
    assert stats.malformed_lines == 0

    # Corrupt .gz file raises clear ValueError
    bad_gz = tmp_path / "corrupt.log.gz"
    bad_gz.write_bytes(b"not a valid gzip stream")
    with pytest.raises(ValueError, match="Failed to decompress gzip"):
        list(parse_log_file(bad_gz, log_format="nginx"))


def test_zip_compressed_log_streaming(tmp_path: Path) -> None:
    zip_path = tmp_path / "logs.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("logs/", "")
        zf.writestr(
            "logs/part1.log",
            "Nov 25 10:01:04 host sshd[101]: Invalid user admin from 203.0.113.5 port 4412\n",
        )
        zf.writestr(
            "logs/part2.log",
            "Nov 25 10:01:08 host sshd[102]: Failed password for root from 203.0.113.5 port 4413 ssh2\n",
        )

    assert detect_log_format(zip_path) == "auth"
    entries = list(parse_log_file(zip_path, log_format="auto", default_year=2026))
    assert len(entries) == 2
    assert entries[0].source_ip == "203.0.113.5"
    assert entries[1].endpoint_or_service == "sshd"

    bad_zip = tmp_path / "corrupt.zip"
    bad_zip.write_bytes(b"not a zip archive")
    with pytest.raises(ValueError, match="Invalid zip archive"):
        list(parse_log_file(bad_zip, log_format="generic"))


def test_malformed_and_invalid_encoding_lines_tracked_gracefully(tmp_path: Path) -> None:
    corrupt_log = tmp_path / "mixed_corrupt.log"
    corrupt_log.write_bytes(
        b'10.0.0.1 - - [25/Nov/2026:10:00:00 +0000] "GET /ok HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n'
        b"\n"
        b"GARBAGE CORRUPTED LINE WITHOUT NGINX STRUCTURE\n"
        b'10.0.0.2 - - [25/Nov/2026:10:00:02 +0000] "GET /bad\xff\xfe HTTP/1.1" 400 10 "-" "curl/8.0"\n'
    )
    stats = ParseStats()
    entries = list(parse_log_file(corrupt_log, log_format="nginx", stats=stats))
    assert len(entries) == 3
    assert stats.total_lines == 4
    assert stats.parsed_lines == 1
    assert stats.blank_lines == 1
    assert stats.malformed_lines == 2
    assert stats.skipped_or_malformed == 3
    assert entries[0].is_malformed is False
    assert entries[1].is_malformed is True
    assert entries[2].is_malformed is True


def test_parse_invalid_format_and_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported log format"):
        list(parse_log_lines(["hello"], log_format="unknown"))

    with pytest.raises(FileNotFoundError):
        list(parse_log_file(tmp_path / "does_not_exist.log"))
