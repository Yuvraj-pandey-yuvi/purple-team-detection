"""
schemas/normalizer.py
---------------------
The single function your detection engine calls: parse_raw_log().

WHY A SINGLE ENTRY POINT:
Your engine currently calls different parsers for different sources.
With a normalizer, the engine loop becomes:

    for line in all_log_lines:
        event = parse_raw_log(line, source=LogSource.AUDITD)
        if event is None:
            parse_error_count += 1
            continue
        for rule in rules:
            alerts.extend(rule.detect(event))

This is the Log Normalization layer that security platforms like
Splunk CIM, Elastic ECS, and Chronicle UDIS all implement — you're
building your own lightweight version.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from typing import Optional, Union

from pydantic import ValidationError

from .base import BaseLogEvent, LogSource
from .auditd import AuditdEvent
from .auth_log import AuthLogEvent
from .cloudtrail import CloudTrailEvent

logger = logging.getLogger(__name__)

# Type alias for the union of all event types
LogEvent = Union[AuditdEvent, AuthLogEvent, CloudTrailEvent]

# ── auditd grouping ───────────────────────────────────────────────────────────

_AUDIT_RE = re.compile(r"msg=audit\((\d+\.\d+):(\d+)\)")
_KV_RE    = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def _parse_kv(line: str) -> dict:
    return {k: (v1 if v1 is not None else v2)
            for k, v1, v2 in _KV_RE.findall(line)}


def group_audit_lines(audit_log: str) -> list[dict]:
    """Group raw auditd text into merged dicts, one per logical event.

    auditd writes one event as multiple lines sharing a serial number:
      type=SYSCALL msg=audit(1705312200.123:456): exe="/tmp/evil" key="shadow_access"
      type=PATH    msg=audit(1705312200.123:456): name="/etc/shadow"

    Steps:
      1. Group lines by serial number
      2. Take SYSCALL as primary record
      3. Add only 'name' from PATH record
      4. Return list of merged dicts ready for AuditdEvent.from_dict()
    """
    groups: dict[str, list[str]] = defaultdict(list)
    for line in audit_log.split("\n"):
        if not line.strip():
            continue
        m = _AUDIT_RE.search(line)
        if m:
            serial = m.group(2)
            groups[serial].append(line)

    result = []
    for serial, lines in groups.items():
        syscall_line = next((l for l in lines if "type=SYSCALL" in l), None)
        path_line    = next((l for l in lines if "type=PATH"    in l), None)

        if not syscall_line:
            continue

        merged = _parse_kv(syscall_line)
        merged["_raw_syscall"] = syscall_line     # preserve for raw field

        if path_line:
            path_fields = _parse_kv(path_line)
            if "name" in path_fields:
                merged["name"] = path_fields["name"]

        result.append(merged)

    return result


def parse_raw_log(
    raw: str,
    source: LogSource,
    *,
    strict: bool = False,
) -> Optional[LogEvent]:
    """Parse a raw log line into a typed, validated event object.

    Args:
        raw:    The raw log line or JSON string.
        source: Which log source produced this line.
        strict: If True, re-raise ValidationError instead of returning None.
                Use strict=True in tests. Use strict=False in the engine loop
                so one bad line doesn't crash the pipeline.

    Returns:
        A validated LogEvent subclass, or None if parsing failed.

    Usage in detection engine:
        event = parse_raw_log(line, LogSource.AUDITD)
        if event is None:
            stats["parse_errors"] += 1
            continue
        # event.auid, event.exe, event.key — all typed
    """
    try:
        if source == LogSource.AUDITD:
            return AuditdEvent.from_raw(raw)

        elif source == LogSource.AUTH_LOG:
            return AuthLogEvent.from_raw(raw)

        elif source == LogSource.CLOUDTRAIL:
            # CloudTrail lines from S3 are JSON objects
            record = json.loads(raw)
            return CloudTrailEvent.from_record(record)

        else:
            logger.warning("Unknown log source: %s", source)
            return None

    except (ValidationError, json.JSONDecodeError, ValueError) as exc:
        if strict:
            raise
        logger.debug(
            "Failed to parse %s log line: %s\nLine: %.200s",
            source.value, exc, raw
        )
        return None


def parse_cloudtrail_file(json_str: str) -> tuple[list[CloudTrailEvent], int]:
    """Parse a full CloudTrail JSON file (the {"Records": [...]} format from S3).
    
    Returns (events, error_count).
    
    Usage:
        with open("cloudtrail_2024-01-15.json") as f:
            events, errors = parse_cloudtrail_file(f.read())
    """
    events = []
    errors = 0
    
    try:
        data = json.loads(json_str)
        records = data.get("Records", [])
    except json.JSONDecodeError as exc:
        logger.error("CloudTrail file is not valid JSON: %s", exc)
        return [], 1

    for record in records:
        try:
            events.append(CloudTrailEvent.from_record(record))
        except (ValidationError, ValueError) as exc:
            logger.debug("CloudTrail record parse error: %s", exc)
            errors += 1

    return events, errors


def parse_log_file(
    filepath: str,
    source: LogSource,
) -> tuple[list[LogEvent], int]:
    """Parse an entire log file, returning (events, error_count).
    
    Usage in your log collector:
        auditd_events, errors = parse_log_file("/var/log/audit/audit.log",
                                               LogSource.AUDITD)
    """
    events: list[LogEvent] = []
    errors = 0

    # CloudTrail files are JSON blobs, not line-oriented
    if source == LogSource.CLOUDTRAIL:
        with open(filepath, "r") as f:
            content = f.read()
        return parse_cloudtrail_file(content)

    # auditd files need grouping by serial number before parsing
    if source == LogSource.AUDITD:
        with open(filepath, "r", errors="replace") as f:
            content = f.read()
        groups = group_audit_lines(content)
        for merged in groups:
            try:
                events.append(AuditdEvent.from_dict(merged))
            except (ValidationError, ValueError) as exc:
                errors += 1
                logger.debug("auditd parse error: %s", exc)
        return events, errors

    # auth.log — line oriented
    with open(filepath, "r", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            event = parse_raw_log(line, source)
            if event is None:
                errors += 1
                logger.debug("Parse error at %s line %d", filepath, lineno)
            else:
                events.append(event)

    if errors:
        logger.warning(
            "%s: %d/%d lines failed validation",
            filepath, errors, errors + len(events)
        )

    return events, errors