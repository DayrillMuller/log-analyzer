"""Streaming, memory-efficient multi-format log parsers with compression and fault tolerance."""

from __future__ import annotations

import gzip
import io
import itertools
import json
import re
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional, Union

SUPPORTED_FORMATS: tuple[str, ...] = ("auto", "nginx", "auth", "syslog", "generic")

ProgressCallback = Callable[[int, int], None]


@dataclass(slots=True)
class ParseStats:
    """Tracks parse health metrics across a log stream."""

    total_lines: int = 0
    parsed_lines: int = 0
    malformed_lines: int = 0
    blank_lines: int = 0

    @property
    def skipped_or_malformed(self) -> int:
        return self.blank_lines + self.malformed_lines

    def to_dict(self) -> dict[str, int]:
        return {
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "malformed_lines": self.malformed_lines,
            "blank_lines": self.blank_lines,
            "skipped_or_malformed": self.skipped_or_malformed,
        }


@dataclass(slots=True)
class LogEntry:
    """Normalized representation of a single parsed log record."""

    timestamp: Optional[datetime]
    source_ip: Optional[str]
    level: str
    endpoint_or_service: Optional[str]
    status_code: Optional[int]
    message: str
    raw_line: str
    line_number: int
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    is_malformed: bool = False


# ---------------------------------------------------------------------------
# Compiled regular expressions for log formats
# ---------------------------------------------------------------------------

# Nginx / Apache Combined & Common Log Format
_NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# RFC 3164 BSD syslog / Linux auth.log: "Nov 25 10:15:32 host proc[123]: msg"
_BSD_SYSLOG_RE = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<service>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$'
)

# ISO-8601 rsyslog / journald syslog: "2026-11-25T10:15:32+00:00 host proc[123]: msg"
_ISO_SYSLOG_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<service>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$'
)

# RFC 5424 syslog: "<PRI>1 2026-11-25T10:15:32Z host app pid msgid - msg"
_RFC5424_SYSLOG_RE = re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<service>\S+)\s+'
    r'(?P<pid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?:(?:\[[^\]]*\])+|-)\s*'
    r'(?P<message>.*)$'
)

# Generic structured application log:
# "2026-11-25 10:15:32,123 [ERROR] service - message" or
# "2026/11/25 10:15:32 [error] ..."
_GENERIC_APP_RE = re.compile(
    r'^(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'[\[(]?(?P<level>TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRIT|CRITICAL|FATAL|ALERT|EMERG)[\])]?\s*'
    r'(?:(?P<service>[A-Za-z0-9_.\-/]+)\s*[-:]\s*)?'
    r'(?P<message>.*)$',
    re.IGNORECASE,
)

# Helper extractors
_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
)
_IPV6_RE = re.compile(
    r'(?<![:\w])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![:\w])'
)
_IP_LABELED_RE = re.compile(
    r'(?:\bfrom\s+|\brhost=|\bsrc=|\bip=|\bclient=)(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)',
    re.IGNORECASE,
)
_STATUS_CODE_RE = re.compile(
    r'\b(?:status|code|http_status)[=:\s]+(?P<status>[1-5]\d{2})\b',
    re.IGNORECASE,
)
_ISO_TS_INLINE_RE = re.compile(
    r'\b(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b'
)
_UA_INLINE_RE = re.compile(r'\b(?:ua|user_agent)="([^"]+)"', re.IGNORECASE)

_AUTH_SERVICE_KEYWORDS = frozenset(
    {
        "sshd",
        "sudo",
        "su",
        "login",
        "passwd",
        "useradd",
        "usermod",
        "groupadd",
        "chpasswd",
        "systemd-logind",
        "polkitd",
        "pam",
    }
)
_AUTH_MESSAGE_HINTS = re.compile(
    r'(?:Failed password|Accepted (?:password|publickey)|Invalid user|authentication failure|'
    r'pam_unix|NOT in sudoers|incorrect password attempts|Connection closed by authenticating user)',
    re.IGNORECASE,
)

_LEVEL_MAP: dict[str, str] = {
    "TRACE": "DEBUG",
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "NOTICE": "INFO",
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "ERR": "ERROR",
    "ERROR": "ERROR",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "ALERT": "CRITICAL",
    "EMERG": "CRITICAL",
}

_SYSLOG_SEVERITY_MAP: dict[int, str] = {
    0: "CRITICAL",  # emerg
    1: "CRITICAL",  # alert
    2: "CRITICAL",  # crit
    3: "ERROR",     # err
    4: "WARNING",   # warning
    5: "INFO",      # notice
    6: "INFO",      # info
    7: "DEBUG",     # debug
}


# ---------------------------------------------------------------------------
# Timestamp and field normalization helpers
# ---------------------------------------------------------------------------

def _to_utc(dt: datetime) -> datetime:
    """Normalize a naive or timezone-aware datetime to UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_flexible_timestamp(
    raw_ts: str,
    default_year: Optional[int] = None,
) -> Optional[datetime]:
    """Parse common log timestamp formats and normalize them to UTC."""
    cleaned = raw_ts.strip()
    if not cleaned or cleaned == "-":
        return None

    year = default_year if default_year is not None else datetime.now(timezone.utc).year

    # 1. ISO-8601 and slash-delimited ISO variants (with optional offset / Z / comma ms)
    iso_candidate = cleaned.replace(",", ".")
    if len(iso_candidate) >= 10 and iso_candidate[4] == "/" and iso_candidate[7] == "/":
        iso_candidate = iso_candidate[:4] + "-" + iso_candidate[5:7] + "-" + iso_candidate[8:]
    if iso_candidate.endswith("Z"):
        iso_candidate = iso_candidate[:-1] + "+00:00"
    try:
        return _to_utc(datetime.fromisoformat(iso_candidate))
    except ValueError:
        pass

    # 2. Nginx / Apache CLF format: 25/Nov/2026:10:15:32 +0000
    for fmt in (
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
        "%Y/%m/%d %H:%M:%S %z",
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            return _to_utc(datetime.strptime(cleaned, fmt))
        except ValueError:
            continue

    # 3. BSD syslog without year: Nov 25 10:15:32
    bsd_norm = " ".join(cleaned.split())
    try:
        return _to_utc(datetime.strptime(f"{year} {bsd_norm}", "%Y %b %d %H:%M:%S"))
    except ValueError:
        pass

    # 4. RFC 2822 / HTTP-date (e.g., Wed, 25 Nov 2026 10:15:32 +0200)
    try:
        dt = parsedate_to_datetime(cleaned)
        if dt is not None:
            return _to_utc(dt)
    except (TypeError, ValueError, IndexError):
        pass

    return None


def _extract_ip(text: str) -> Optional[str]:
    """Extract the most likely source IPv4/IPv6 address from a message."""
    labeled = _IP_LABELED_RE.search(text)
    if labeled:
        candidate = labeled.group("ip")
        if _IPV4_RE.fullmatch(candidate) or ":" in candidate:
            return candidate
    ipv4 = _IPV4_RE.search(text)
    if ipv4:
        return ipv4.group(0)
    ipv6 = _IPV6_RE.search(text)
    if ipv6:
        return ipv6.group(0)
    return None


def _normalize_level(raw_level: str) -> str:
    return _LEVEL_MAP.get(raw_level.strip().upper(), "INFO")


def _infer_level_from_message(message: str) -> str:
    lower = message.lower()
    if any(
        kw in lower
        for kw in (
            "kernel panic",
            "segfault",
            "segmentation fault",
            "oom-killer",
            "out of memory",
            "core dumped",
            "fatal",
            "critical",
            "code=killed",
        )
    ):
        return "CRITICAL"
    if any(
        kw in lower
        for kw in (
            "failed password",
            "authentication failure",
            "incorrect password",
            "not in sudoers",
            "command not allowed",
            "error",
            "denied",
            "unauthorized",
            "refused",
        )
    ):
        return "ERROR"
    if any(
        kw in lower
        for kw in (
            "invalid user",
            "warn",
            "disconnect",
            "closed by authenticating",
            "too many authentication",
            "maximum authentication",
            "locked",
        )
    ):
        return "WARNING"
    return "INFO"


def _level_from_http_status(status_code: Optional[int]) -> str:
    if status_code is None:
        return "INFO"
    if status_code >= 500:
        return "ERROR"
    if status_code >= 400:
        return "WARNING"
    return "INFO"


def _extract_user_agent(text: str) -> Optional[str]:
    match = _UA_INLINE_RE.search(text)
    if match:
        ua = match.group(1).strip()
        return None if ua == "-" else ua
    return None


# ---------------------------------------------------------------------------
# Streaming file & archive readers (.txt/.log, .gz, .zip)
# ---------------------------------------------------------------------------

def get_stream_total_bytes(file_path: Union[str, Path]) -> int:
    """Return total bytes expected for progress tracking across plain, .gz, or .zip files."""
    path = Path(file_path)
    if not path.is_file():
        return 0
    suffix = path.suffix.lower()
    if suffix == ".zip":
        try:
            with zipfile.ZipFile(path, "r") as zf:
                return sum(
                    info.file_size
                    for info in zf.infolist()
                    if not info.is_dir() and not info.filename.startswith("__MACOSX/")
                )
        except zipfile.BadZipFile:
            return path.stat().st_size
    return path.stat().st_size


@contextmanager
def _open_log_stream(
    file_path: Path,
    progress_callback: Optional[ProgressCallback] = None,
) -> Iterator[Iterator[str]]:
    """Open a plain-text, .gz, or .zip log file as a line-by-line UTF-8 text iterator."""
    suffix = file_path.suffix.lower()

    if suffix == ".gz":
        with file_path.open("rb") as raw_fh:
            try:
                with gzip.open(raw_fh, mode="rt", encoding="utf-8", errors="replace") as gz_fh:
                    def _gz_iter() -> Iterator[str]:
                        last_pos = 0
                        for line in gz_fh:
                            if progress_callback is not None:
                                cur_pos = raw_fh.tell()
                                delta = max(0, cur_pos - last_pos)
                                last_pos = cur_pos
                                progress_callback(delta, 1)
                            yield line

                    yield _gz_iter()
            except (OSError, EOFError, gzip.BadGzipFile) as exc:
                raise ValueError(f"Failed to decompress gzip file '{file_path}': {exc}") from exc
        return

    if suffix == ".zip":
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                members = [
                    info
                    for info in zf.infolist()
                    if not info.is_dir() and not info.filename.startswith("__MACOSX/")
                ]

                def _zip_iter() -> Iterator[str]:
                    for info in members:
                        with zf.open(info, "r") as raw_member:
                            wrapper = io.TextIOWrapper(
                                raw_member,
                                encoding="utf-8",
                                errors="replace",
                            )
                            try:
                                for line in wrapper:
                                    if progress_callback is not None:
                                        progress_callback(len(line.encode("utf-8", errors="replace")), 1)
                                    yield line
                            finally:
                                wrapper.detach()

                yield _zip_iter()
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Invalid zip archive '{file_path}': {exc}") from exc
        return

    # Plain-text log file
    with file_path.open("rb") as raw_fh:
        wrapper = io.TextIOWrapper(raw_fh, encoding="utf-8", errors="replace")
        try:
            def _plain_iter() -> Iterator[str]:
                last_pos = 0
                for line in wrapper:
                    if progress_callback is not None:
                        cur_pos = raw_fh.tell()
                        delta = max(0, cur_pos - last_pos)
                        last_pos = cur_pos
                        progress_callback(delta, 1)
                    yield line

            yield _plain_iter()
        finally:
            wrapper.detach()


# ---------------------------------------------------------------------------
# Per-format single-line parsers
# ---------------------------------------------------------------------------

def _parse_nginx_line(raw_line: str, line_number: int) -> LogEntry:
    match = _NGINX_RE.match(raw_line)
    if not match:
        fallback = _parse_generic_line(raw_line, line_number)
        fallback.is_malformed = True
        return fallback

    ip = match.group("ip")
    source_ip = None if ip == "-" else ip
    timestamp = parse_flexible_timestamp(match.group("timestamp"))
    request = match.group("request").strip()
    status_str = match.group("status")
    status_code = int(status_str) if status_str.isdigit() else None
    referer = match.group("referer") or "-"
    raw_ua = match.group("user_agent") or "-"
    user_agent = None if raw_ua == "-" else raw_ua

    parts = request.split()
    if len(parts) >= 2:
        endpoint = f"{parts[0]} {parts[1]}"
        request_path = parts[1]
    else:
        endpoint = request or None
        request_path = request or None

    message = f'{request} status={status_str} referer="{referer}" ua="{raw_ua}"'
    is_malformed = timestamp is None or "\ufffd" in raw_line
    return LogEntry(
        timestamp=timestamp,
        source_ip=source_ip,
        level=_level_from_http_status(status_code),
        endpoint_or_service=endpoint,
        status_code=status_code,
        message=message,
        raw_line=raw_line,
        line_number=line_number,
        user_agent=user_agent,
        request_path=request_path,
        is_malformed=is_malformed,
    )


def _parse_syslog_or_auth_line(
    raw_line: str,
    line_number: int,
    default_year: int,
) -> LogEntry:
    # 1. RFC 5424
    rfc_match = _RFC5424_SYSLOG_RE.match(raw_line)
    if rfc_match:
        pri = int(rfc_match.group("pri"))
        level = _SYSLOG_SEVERITY_MAP.get(pri % 8, "INFO")
        ts_raw = rfc_match.group("timestamp")
        timestamp = parse_flexible_timestamp(ts_raw, default_year=default_year)
        service = rfc_match.group("service")
        message = rfc_match.group("message")
        inferred = _infer_level_from_message(message)
        if level == "INFO" and inferred != "INFO":
            level = inferred
        return LogEntry(
            timestamp=timestamp,
            source_ip=_extract_ip(message),
            level=level,
            endpoint_or_service=None if service == "-" else service,
            status_code=None,
            message=message,
            raw_line=raw_line,
            line_number=line_number,
            is_malformed="\ufffd" in raw_line,
        )

    # 2. ISO-8601 syslog
    iso_match = _ISO_SYSLOG_RE.match(raw_line)
    if iso_match:
        timestamp = parse_flexible_timestamp(iso_match.group("timestamp"), default_year=default_year)
        service = iso_match.group("service")
        message = iso_match.group("message")
        return LogEntry(
            timestamp=timestamp,
            source_ip=_extract_ip(message),
            level=_infer_level_from_message(message),
            endpoint_or_service=service,
            status_code=None,
            message=message,
            raw_line=raw_line,
            line_number=line_number,
            is_malformed=timestamp is None or "\ufffd" in raw_line,
        )

    # 3. BSD RFC 3164 syslog / Linux auth.log
    bsd_match = _BSD_SYSLOG_RE.match(raw_line)
    if bsd_match:
        timestamp = parse_flexible_timestamp(bsd_match.group("timestamp"), default_year=default_year)
        service = bsd_match.group("service")
        message = bsd_match.group("message")
        return LogEntry(
            timestamp=timestamp,
            source_ip=_extract_ip(message),
            level=_infer_level_from_message(message),
            endpoint_or_service=service,
            status_code=None,
            message=message,
            raw_line=raw_line,
            line_number=line_number,
            is_malformed=timestamp is None or "\ufffd" in raw_line,
        )

    fallback = _parse_generic_line(raw_line, line_number)
    fallback.is_malformed = True
    return fallback


def _parse_json_line(raw_line: str, line_number: int) -> Optional[LogEntry]:
    stripped = raw_line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    raw_ts = payload.get("timestamp") or payload.get("time") or payload.get("@timestamp")
    timestamp = parse_flexible_timestamp(str(raw_ts)) if raw_ts else None

    source_ip = (
        payload.get("source_ip")
        or payload.get("client_ip")
        or payload.get("ip")
        or payload.get("remote_addr")
    )
    if source_ip is not None:
        source_ip = str(source_ip)

    raw_status = payload.get("status_code") or payload.get("status")
    status_code = int(raw_status) if str(raw_status).isdigit() else None

    raw_level = payload.get("level") or payload.get("severity")
    message = str(payload.get("message") or payload.get("msg") or raw_line)
    level = _normalize_level(str(raw_level)) if raw_level else _infer_level_from_message(message)

    endpoint_or_service = (
        payload.get("endpoint")
        or payload.get("path")
        or payload.get("service")
        or payload.get("logger")
    )
    if endpoint_or_service is not None:
        endpoint_or_service = str(endpoint_or_service)

    request_path = payload.get("path") or payload.get("endpoint")
    user_agent = payload.get("user_agent") or payload.get("ua")

    if source_ip is None:
        source_ip = _extract_ip(message)

    return LogEntry(
        timestamp=timestamp,
        source_ip=source_ip,
        level=level,
        endpoint_or_service=endpoint_or_service,
        status_code=status_code,
        message=message,
        raw_line=raw_line,
        line_number=line_number,
        user_agent=str(user_agent) if user_agent else None,
        request_path=str(request_path) if request_path else None,
        is_malformed="\ufffd" in raw_line,
    )


def _parse_generic_line(raw_line: str, line_number: int) -> LogEntry:
    json_entry = _parse_json_line(raw_line, line_number)
    if json_entry is not None:
        return json_entry

    app_match = _GENERIC_APP_RE.match(raw_line)
    if app_match:
        timestamp = parse_flexible_timestamp(app_match.group("timestamp"))
        level = _normalize_level(app_match.group("level"))
        service = app_match.group("service")
        message = app_match.group("message")
        status_match = _STATUS_CODE_RE.search(message)
        status_code = int(status_match.group("status")) if status_match else None
        return LogEntry(
            timestamp=timestamp,
            source_ip=_extract_ip(message),
            level=level,
            endpoint_or_service=service,
            status_code=status_code,
            message=message,
            raw_line=raw_line,
            line_number=line_number,
            user_agent=_extract_user_agent(message),
            is_malformed=timestamp is None or "\ufffd" in raw_line,
        )

    # Best-effort fallback for unstructured or corrupted lines
    ts_match = _ISO_TS_INLINE_RE.search(raw_line)
    timestamp = parse_flexible_timestamp(ts_match.group("ts")) if ts_match else None
    source_ip = _extract_ip(raw_line)
    status_match = _STATUS_CODE_RE.search(raw_line)
    status_code = int(status_match.group("status")) if status_match else None
    is_malformed = ("\ufffd" in raw_line) or (
        timestamp is None and source_ip is None and status_code is None
    )
    return LogEntry(
        timestamp=timestamp,
        source_ip=source_ip,
        level=_infer_level_from_message(raw_line),
        endpoint_or_service=None,
        status_code=status_code,
        message=raw_line,
        raw_line=raw_line,
        line_number=line_number,
        user_agent=_extract_user_agent(raw_line),
        is_malformed=is_malformed,
    )


# ---------------------------------------------------------------------------
# Auto-detection and public streaming generators
# ---------------------------------------------------------------------------

def detect_log_format(
    source: Union[str, Path, Iterable[str]],
    sample_size: int = 25,
) -> str:
    """Inspect up to `sample_size` non-empty lines and infer the log format.

    Transparently supports plain-text files, .gz files, .zip archives, or line iterables.
    Returns one of: 'nginx', 'auth', 'syslog', 'generic'.
    """
    sample_lines: list[str] = []
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {path}")
        with _open_log_stream(path) as stream:
            for line in stream:
                stripped = line.strip()
                if stripped:
                    sample_lines.append(stripped)
                    if len(sample_lines) >= sample_size:
                        break
    else:
        for line in source:
            stripped = line.strip()
            if stripped:
                sample_lines.append(stripped)
                if len(sample_lines) >= sample_size:
                    break

    if not sample_lines:
        return "generic"

    scores: dict[str, int] = {"nginx": 0, "auth": 0, "syslog": 0, "generic": 0}
    for line in sample_lines:
        if _NGINX_RE.match(line):
            scores["nginx"] += 3
            continue

        syslog_match = (
            _RFC5424_SYSLOG_RE.match(line)
            or _ISO_SYSLOG_RE.match(line)
            or _BSD_SYSLOG_RE.match(line)
        )
        if syslog_match:
            service = (syslog_match.group("service") or "").lower()
            message = syslog_match.group("message") or ""
            if service in _AUTH_SERVICE_KEYWORDS or _AUTH_MESSAGE_HINTS.search(message):
                scores["auth"] += 3
            else:
                scores["syslog"] += 2
            continue

        scores["generic"] += 1

    best_format = max(
        ("nginx", "auth", "syslog", "generic"),
        key=lambda fmt: scores[fmt],
    )
    return best_format if scores[best_format] > 0 else "generic"


def parse_log_lines(
    lines: Iterable[str],
    log_format: str = "auto",
    default_year: Optional[int] = None,
    sample_size: int = 25,
    stats: Optional[ParseStats] = None,
) -> Iterator[LogEntry]:
    """Stream normalized LogEntry objects from an iterable of raw log lines.

    Uses O(1) memory: when `log_format == 'auto'`, buffers at most `sample_size`
    non-empty lines to detect the format, then streams every line lazily.
    Populates `stats` (if provided) with parse health counters.
    """
    fmt = log_format.lower().strip()
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported log format '{log_format}'. "
            f"Choose one of: {', '.join(SUPPORTED_FORMATS)}."
        )

    year = default_year if default_year is not None else datetime.now(timezone.utc).year
    line_iter = iter(lines)

    if fmt == "auto":
        buffered: list[str] = []
        non_empty = 0
        for raw in line_iter:
            buffered.append(raw)
            if raw.strip():
                non_empty += 1
                if non_empty >= sample_size:
                    break
        fmt = detect_log_format(buffered, sample_size=sample_size)
        stream: Iterable[str] = itertools.chain(buffered, line_iter)
    else:
        stream = line_iter

    for line_number, raw in enumerate(stream, start=1):
        if stats is not None:
            stats.total_lines += 1

        cleaned = raw.rstrip("\r\n")
        if not cleaned.strip():
            if stats is not None:
                stats.blank_lines += 1
            continue

        if fmt == "nginx":
            entry = _parse_nginx_line(cleaned, line_number)
        elif fmt in ("auth", "syslog"):
            entry = _parse_syslog_or_auth_line(cleaned, line_number, year)
        else:
            entry = _parse_generic_line(cleaned, line_number)

        if stats is not None:
            if entry.is_malformed:
                stats.malformed_lines += 1
            else:
                stats.parsed_lines += 1

        yield entry


def parse_log_file(
    file_path: Union[str, Path],
    log_format: str = "auto",
    default_year: Optional[int] = None,
    sample_size: int = 25,
    stats: Optional[ParseStats] = None,
    progress_callback: Optional[ProgressCallback] = None,
) -> Iterator[LogEntry]:
    """Stream normalized LogEntry objects line-by-line from plain, .gz, or .zip logs."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    with _open_log_stream(path, progress_callback=progress_callback) as line_stream:
        yield from parse_log_lines(
            line_stream,
            log_format=log_format,
            default_year=default_year,
            sample_size=sample_size,
            stats=stats,
        )
