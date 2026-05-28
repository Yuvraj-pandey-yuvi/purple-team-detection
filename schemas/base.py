"""
schemas/base.py
---------------
Shared enums and the BaseLogEvent that every log source inherits from.

WHY A BASE CLASS:
Your detection engine loops over mixed log sources. Without a common
base, every rule has to guess which fields exist. With BaseLogEvent,
every rule can safely access .timestamp, .source, .raw — always.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


# ── Enumerations ────────────────────────────────────────────────────────────

class LogSource(str, Enum):
    """Which collector produced this event."""
    AUDITD    = "auditd"
    AUTH_LOG  = "auth_log"
    CLOUDTRAIL = "cloudtrail"


class Severity(str, Enum):
    """Severity levels used across all detection rules.
    
    Stored as strings so they serialize cleanly in JSON reports
    without needing a custom encoder.
    """
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_count(cls, n: int) -> "Severity":
        """Utility: derive severity from a raw count (e.g. SSH attempts)."""
        if n >= 50:   return cls.CRITICAL
        if n >= 20:   return cls.HIGH
        if n >= 10:   return cls.MEDIUM
        if n >= 3:    return cls.LOW
        return cls.INFO


class AttackSpeed(str, Enum):
    """Attack speed classification for brute-force rules (T1110.001)."""
    AGGRESSIVE = "aggressive"    # > 10 attempts / 60 sec
    MODERATE   = "moderate"      # 3–10 attempts / 60 sec
    SLOW_SCAN  = "slow_scan"     # < 3 attempts / 60 sec


class ATTCKTechnique(str, Enum):
    """MITRE ATT&CK technique IDs covered by this pipeline.
    
    Enum (not free-form string) because typos in technique IDs
    produce silently wrong coverage reports.
    """
    T1110_001 = "T1110.001"   # Brute Force: Password Guessing
    T1136_001 = "T1136.001"   # Create Local Account
    T1003_008 = "T1003.008"   # OS Credential Dumping (/etc/shadow)
    T1036     = "T1036"       # Masquerading
    T1053_003 = "T1053.003"   # Scheduled Task: Cron
    T1078     = "T1078"       # Valid Accounts


# ── Base event ───────────────────────────────────────────────────────────────

class BaseLogEvent(BaseModel):
    """Fields that EVERY log event from every source must have.
    
    Your detection engine can iterate mixed log lists and always
    safely access these fields without isinstance() checks.
    """

    source: LogSource
    """Which collector produced this event."""

    timestamp: datetime
    """Normalized to UTC. Validators on each subclass handle format differences:
    - auditd:     Unix epoch float  ("1705312200.123")
    - auth_log:   syslog string     ("Jan 15 10:30:00")
    - CloudTrail: ISO-8601 string   ("2024-01-15T10:30:00Z")
    All become aware datetime objects here.
    """

    raw: str
    """The original log line, unmodified. Always kept so you can:
    - Re-parse with a new rule without re-reading files
    - Include in alert context for analyst review
    - Write to SIEM without data loss
    """

    extra: dict[str, Any] = Field(default_factory=dict)
    """Catch-all for source-specific fields not in the typed schema.
    Rules shouldn't depend on this — it's for forensic preservation.
    """

    model_config = {
        "frozen": True,          # Events are immutable after parsing
        "extra": "allow",        # Don't crash on unknown fields — log sources add fields
        "str_strip_whitespace": True,
    }

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc(cls, v: Any) -> datetime:
        """Accepts datetime objects and makes them UTC-aware.
        Subclasses parse strings into datetime first, then this runs.
        """
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        # Numeric epoch
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        raise ValueError(f"Cannot coerce {type(v)} to datetime: {v!r}")

    @property
    def epoch(self) -> float:
        """Unix timestamp as float. Convenience for sliding-window rule math."""
        return self.timestamp.timestamp()