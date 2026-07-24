"""
schemas/auth_log.py
-------------------
Schema for /var/log/auth.log events — your source for:
  T1110.001  SSH brute force (Failed password for ...)
  T1136.001  New user creation (new user: name=..., useradd)

auth.log lines look like:
  Jan 15 10:30:00 hostname sshd[12345]: Failed password for root from 178.175.167.68 port 22 ssh2
  Jan 15 10:31:05 hostname useradd[12346]: new user: name=attacker, UID=1001, GID=1001, ...
  Jan 15 10:31:05 hostname sudo[12347]: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/sbin/useradd attacker
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional
from ipaddress import IPv4Address, IPv6Address, ip_address

from pyparsing import line
from pydantic import Field, field_validator, IPvAnyAddress

from .base import BaseLogEvent, LogSource

# ── Regexes for common auth.log patterns ─────────────────────────────────────

_SSH_FAIL   = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+) port (\d+)"
)
_SSH_ACCEPT = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.a-fA-F:]+) port (\d+)"
)
_NEW_USER   = re.compile(
    r"new user[^:]*:\s*name=(\S+?),"
)
_USERADD_CMD = re.compile(
    r"COMMAND=.*useradd\s+(\S+)"
)
_SUDO_USER  = re.compile(
    r"(\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.*)"
)
# syslog timestamp: "Jan 15 10:30:00"  (no year — we'll use current year)
_SYSLOG_TS  = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
# Add this regex alongside _SYSLOG_TS
_ISO_TS = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*[+-]\d{2}:\d{2})')
_SYSLOG_FMT = "%b %d %H:%M:%S"


class AuthLogEvent(BaseLogEvent):
    """A parsed /var/log/auth.log event."""

    source: LogSource = LogSource.AUTH_LOG

    # ── Who/where ────────────────────────────────────────────────────────────
    hostname: str = ""
    process: str  = Field(default="", description="e.g. 'sshd', 'sudo', 'useradd'")
    pid: Optional[int] = None

    # ── SSH-specific (T1110.001) ──────────────────────────────────────────────
    auth_result: Optional[str] = None
    """'failed' | 'accepted' | None for non-auth lines."""
    
    username: Optional[str] = None
    """Username attempted. 'root', 'admin', 'invalid user foo', etc."""
    
    source_ip: Optional[str] = None
    """Attacker IP. Stored as string for JSON serialization;
    validated as a real IP address on ingestion.
    """
    
    port: Optional[int] = None
    auth_method: Optional[str] = None  # 'password', 'publickey'

    # ── User-creation-specific (T1136.001) ───────────────────────────────────
    new_username: Optional[str] = None
    """Set when this line records a new account being created."""
    
    sudo_command: Optional[str] = None
    """Full COMMAND= from sudo log lines. Useful for creator attribution."""
    
    sudo_user: Optional[str] = None
    """Who ran sudo."""

    # ── Validators ───────────────────────────────────────────────────────────
    @field_validator("source_ip", mode="before")
    @classmethod
    def validate_ip(cls, v):
        """Reject invalid IPs instead of storing garbage strings.
        
        WHY THIS MATTERS: your geolocation map breaks silently on
        malformed IPs. Better to catch at parse time.
        """
        if v is None:
            return None
        try:
            ip_address(str(v))  # validates both IPv4 and IPv6
            return str(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")

    

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_syslog_ts(cls, v):
        if isinstance(v, str):
        # Try ISO-8601 first (newer Ubuntu)
            m = _ISO_TS.match(v)
            if m:
                return datetime.fromisoformat(m.group(1))
        # Fall back to syslog format (older Ubuntu)
            m = _SYSLOG_TS.match(v)
            if m:
                current_year = datetime.now().year
                parsed = datetime.strptime(
                f"{current_year} {m.group(1).strip()}",
                f"%Y {_SYSLOG_FMT}"
                 )
                return parsed.replace(tzinfo=timezone.utc)
        return v

    # ── Factory ──────────────────────────────────────────────────────────────
    @classmethod
    def from_raw(cls, raw_line: str) -> "AuthLogEvent":
        """Parse a raw auth.log line into a validated AuthLogEvent.
        
        Parses common patterns; unparseable lines get source+raw+timestamp
        and empty optional fields — the rule can inspect .raw if needed.
        """
        line = raw_line.strip()
        
        # --- Extract timestamp (first 15 chars of syslog lines) ---
        #ts_str = line[:15] if len(line) >= 15 else line

         # Extract timestamp — handle both formats
        m_iso = _ISO_TS.match(line)
        m_sys = _SYSLOG_TS.match(line)
        ts_str = m_iso.group(1) if m_iso else (m_sys.group(1) if m_sys else line[:15])

        # --- Extract hostname and process ---
        parts = line.split()
        hostname = parts[3] if len(parts) > 3 else ""
        process_pid = parts[4] if len(parts) > 4 else ""
        
        process = ""
        pid = None
        if "[" in process_pid:
            proc_parts = process_pid.rstrip(":").split("[")
            process = proc_parts[0]
            try:
                pid = int(proc_parts[1].rstrip("]"))
            except (IndexError, ValueError):
                pass
        else:
            process = process_pid.rstrip(":")

        # --- SSH failed auth (T1110.001) ---
        m = _SSH_FAIL.search(line)
        if m:
            return cls(
                source=LogSource.AUTH_LOG,
                timestamp=ts_str,
                raw=raw_line,
                hostname=hostname,
                process=process,
                pid=pid,
                auth_result="failed",
                username=m.group(1),
                source_ip=m.group(2),
                port=int(m.group(3)),
                auth_method="password",
            )

        # --- SSH accepted auth ---
        m = _SSH_ACCEPT.search(line)
        if m:
            return cls(
                source=LogSource.AUTH_LOG,
                timestamp=ts_str,
                raw=raw_line,
                hostname=hostname,
                process=process,
                pid=pid,
                auth_result="accepted",
                username=m.group(1),
                source_ip=m.group(2),
                port=int(m.group(3)),
            )

        # --- New user creation (T1136.001) ---
        m = _NEW_USER.search(line)
        if m:
            return cls(
                source=LogSource.AUTH_LOG,
                timestamp=ts_str,
                raw=raw_line,
                hostname=hostname,
                process=process,
                pid=pid,
                new_username=m.group(1),
            )

        # --- Sudo command (creator attribution for T1136.001) ---
        m = _SUDO_USER.search(line)
        if m:
            return cls(
                source=LogSource.AUTH_LOG,
                timestamp=ts_str,
                raw=raw_line,
                hostname=hostname,
                process=process,
                pid=pid,
                sudo_user=m.group(1),
                sudo_command=m.group(3).strip(),
            )

        # --- Unparseable: preserve with empty optionals ---
        return cls(
            source=LogSource.AUTH_LOG,
            timestamp=ts_str,
            raw=raw_line,
            hostname=hostname,
            process=process,
            pid=pid,
        )