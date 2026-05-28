"""
schemas/auditd.py
-----------------
Schema for Linux auditd events — your primary source for:
  T1003.008  /etc/shadow access
  T1036      Masquerading (exe path mismatch)
  T1053.003  Cron modification
  T1136.001  User creation (secondary signal)

auditd log lines look like:
  type=SYSCALL msg=audit(1705312200.123:456): arch=c000003e syscall=2
    success=yes exit=3 a0=7f... a1=0 a2=1b6 a3=0 items=1 ppid=1234
    pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0
    egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="python3"
    exe="/usr/bin/python3" key="shadow_access"
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional
from pydantic import Field, field_validator, model_validator

from .base import BaseLogEvent, LogSource

# ── Regex for the auditd timestamp embedded in msg= ─────────────────────────
_MSG_TS = re.compile(r"msg=audit\((\d+\.\d+):\d+\)")

# ── Regex for key=value pairs in auditd lines ────────────────────────────────
_KV     = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def _parse_auditd_line(raw: str) -> dict:
    """Extract key=value pairs from a raw auditd line.
    
    Returns a flat dict. Quoted values are unquoted.
    Example:  comm="python3" exe="/usr/bin/python3"
           → {"comm": "python3", "exe": "/usr/bin/python3"}
    """
    return {k: (v1 if v1 is not None else v2)
            for k, v1, v2 in _KV.findall(raw)}


class AuditdEvent(BaseLogEvent):
    """A parsed auditd event.
    
    Field names match auditd field names exactly so rules written
    against raw dicts can migrate with minimal changes.
    """

    source: LogSource = LogSource.AUDITD

    # ── Identity fields ──────────────────────────────────────────────────────
    auid: int = Field(description="Audit UID — the original user before su/sudo. "
                                  "4294967295 (0xFFFFFFFF) means unset.")
    uid: int  = Field(description="Real UID at time of syscall.")
    euid: int = Field(description="Effective UID — catches privilege escalation "
                                   "when euid=0 but auid!=0.")
    
    # ── Process fields ───────────────────────────────────────────────────────
    pid: int
    ppid: int = 0
    comm: str = Field(description="Process name from kernel (15 char limit, can be spoofed).")
    exe: str  = Field(description="Full path to executable. Harder to spoof than comm. "
                                   "Use this for masquerading detection (T1036).")
    
    # ── Event classification ─────────────────────────────────────────────────
    syscall: Optional[int] = None
    success: bool = True
    key: Optional[str] = None
    """auditd watch key — the label you set in audit rules.
    e.g. 'shadow_access', 'cron_modification'. Primary routing signal."""

    # ── File access fields (present in PATH records) ─────────────────────────
    name: Optional[str] = None
    """File path accessed. Set in AUDIT_PATH records."""

    record_type: str = Field(default="SYSCALL",
                             description="SYSCALL, PATH, EXECVE, etc.")

    # ── Derived convenience properties ───────────────────────────────────────
    @property
    def is_privileged_escalation(self) -> bool:
        """True when a non-root user's process runs as root.
        Core signal for privilege escalation detection.
        """
        UNSET_AUID = 4294967295
        return (self.euid == 0 and 
                self.auid != 0 and 
                self.auid != UNSET_AUID)

    @property
    def exe_matches_comm(self) -> bool:
        """False = possible masquerading (T1036).
        e.g. comm='python3' but exe='/tmp/.hidden/python3'
        """
        import os
        return os.path.basename(self.exe) == self.comm

    # ── Validators ───────────────────────────────────────────────────────────
    @field_validator("success", mode="before")
    @classmethod
    def coerce_success(cls, v):
        """auditd writes success=yes/no, not true/false."""
        if isinstance(v, str):
            return v.lower() == "yes"
        return bool(v)

    @field_validator("auid", "uid", "euid", "pid", "ppid", mode="before")
    @classmethod
    def coerce_int(cls, v):
        """auditd emits all numeric fields as strings."""
        return int(v)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_auditd_timestamp(cls, v, info):
        """Extract epoch from msg=audit(EPOCH.MS:SERIAL).
        Falls back to the value itself if it's already a number.
        """
        if isinstance(v, str) and "audit(" in v:
            m = _MSG_TS.search(v)
            if m:
                return datetime.fromtimestamp(float(m.group(1)), tz=timezone.utc)
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        return v  # let base validator handle datetime objects

    # ── Factory ──────────────────────────────────────────────────────────────
    @classmethod
    def from_dict(cls, merged: dict) -> "AuditdEvent":
        """Build an AuditdEvent from a merged dict produced by group_audit_lines().

        The merged dict has all SYSCALL fields plus 'name' from PATH.
        Timestamp is extracted from merged['msg'] using _MSG_TS regex.

        Usage:
            groups = group_audit_lines(raw_text)
            events = [AuditdEvent.from_dict(g) for g in groups]
        """
        # Extract epoch from msg=audit(EPOCH:SERIAL)
        # _parse_kv gives us {"msg": "audit(1705312200.123:456)", ...}
        # We still need to pull the epoch out with _MSG_TS
        msg_val  = merged.get("msg", "")
        ts_match = _MSG_TS.search(f"msg={msg_val}")
        timestamp = float(ts_match.group(1)) if ts_match else 0.0

        # Build raw string from the dict for forensic preservation
        # We don't have the original line anymore so reconstruct it
        raw = merged.get("_raw_syscall", str(merged))

        # Known fields — everything else goes to extra
        known = {"auid","uid","euid","pid","ppid","comm","exe",
                 "syscall","success","key","name","type","msg","_raw_syscall"}

        return cls(
            source=LogSource.AUDITD,
            timestamp=timestamp,
            raw=raw,
            auid=merged.get("auid", "4294967295"),
            uid=merged.get("uid", "0"),
            euid=merged.get("euid", "0"),
            pid=merged.get("pid", "0"),
            ppid=merged.get("ppid", "0"),
            comm=merged.get("comm", ""),
            exe=merged.get("exe", ""),
            syscall=merged.get("syscall"),
            success=merged.get("success", "yes"),
            key=merged.get("key"),
            name=merged.get("name"),        # from PATH record, may be None
            record_type=merged.get("type", "SYSCALL"),
            extra={k: v for k, v in merged.items() if k not in known},
        )

    @classmethod
    def from_raw(cls, raw_line: str) -> "AuditdEvent":
        """Parse a single raw auditd line.

        Kept for backward compatibility and testing single lines.
        Internally groups the line (as a one-line 'file') then calls from_dict().
        """
        from .normalizer import group_audit_lines
        groups = group_audit_lines(raw_line)
        if groups:
            return cls.from_dict(groups[0])
        # Fallback: line had no msg=audit(...) — parse directly
        fields = _parse_auditd_line(raw_line)
        return cls.from_dict({**fields, "_raw_syscall": raw_line})