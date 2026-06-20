"""
schemas/alert.py
----------------
Alert and report schemas — the shapes your FastAPI endpoints return.

WHY TYPED SCHEMAS FOR API RESPONSES:
- FastAPI uses these as response_model= to auto-validate output
- Swagger docs become accurate automatically
- Frontend JavaScript gets a stable contract
- Adding a field to Alert is one change, not five

Current API endpoints:
  GET /alerts         → List[Alert]
  GET /report         → AlertReport
  GET /summary        → CoverageSummary
  GET /user-activity  → List[UserActivity]
  GET /attackers      → List[AttackerProfile]
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator

from .base import Severity, ATTCKTechnique, AttackSpeed, LogSource


# ── Core Alert ────────────────────────────────────────────────────────────────

class Alert(BaseModel):
    """A single detection alert. One rule firing = one Alert.
    
    This is the fundamental output of your detection engine.
    Every rule's detect() method should return List[Alert].
    """

    # Identity
    alert_id: Optional[str] = None
    """Optional UUID for deduplication and correlation across sessions."""

    rule_id: str
    """e.g. 'rule_001_ssh_brute_force' — matches your rule filename."""

    technique: ATTCKTechnique
    """MITRE ATT&CK technique. Enum prevents typos in coverage reports."""

    # Severity
    severity: Severity
    
    # Timing
    timestamp: datetime
    """When the alert was generated (not necessarily when the event occurred)."""
    
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    """For aggregated alerts (e.g. brute force campaign), the window."""

    # Actor
    source_ip: Optional[str] = None
    username: Optional[str] = None
    auid: Optional[int] = None
    """Linux audit UID. Cross-reference with username for attribution."""

    # Context
    description: str
    """Human-readable summary. Written for an analyst, not a machine."""
    
    raw_log: Optional[str] = None
    """Original log line(s). Include for analyst review; omit for /summary."""

    log_source: LogSource
    
    # Rule-specific extras
    extra: dict[str, Any] = Field(default_factory=dict)
    """Rule-specific data: attack_speed, count, process_path, etc.
    Don't put critical detection data here — use typed fields above.
    Use extra for supplementary context that varies by rule.
    """

    model_config = {"frozen": True}

    @field_validator("severity", mode="before")
    @classmethod
    def coerce_severity(cls, v):
        """Accept old-style string severities from pre-Pydantic rules.
        
        During migration, existing rules may return raw strings.
        This validator bridges the gap without breaking anything.
        """
        if isinstance(v, str):
            return Severity(v.upper())
        return v

    @field_validator("technique", mode="before")
    @classmethod
    def coerce_technique(cls, v):
        """Accept technique IDs as strings."""
        if isinstance(v, str):
            return ATTCKTechnique(v)
        return v


# ── Attacker Profile (for /attackers endpoint) ────────────────────────────────

class AttackerProfile(BaseModel):
    """Aggregated view of a single attacker IP across all alerts."""
    
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    
    total_attempts: int = 0
    techniques_used: list[ATTCKTechnique] = Field(default_factory=list)
    attack_speed: Optional[AttackSpeed] = None
    
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    is_active: bool = False
    """True if last_seen within last 24 hours."""

    @property
    def threat_score(self) -> int:
        """Simple 0-100 score for dashboard sorting.
        
        Not a substitute for real threat intel — useful for UI only.
        """
        score = min(self.total_attempts * 2, 60)
        score += len(self.techniques_used) * 10
        if self.attack_speed == AttackSpeed.AGGRESSIVE:
            score += 20
        elif self.attack_speed == AttackSpeed.MODERATE:
            score += 10
        return min(score, 100)


# ── User Activity (for /user-activity endpoint) ───────────────────────────────

class UserActivity(BaseModel):
    """Aggregated alert activity per Linux user (auid)."""
    
    auid: int
    username: Optional[str] = None
    
    alert_count: int = 0
    techniques_triggered: list[ATTCKTechnique] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    
    is_privileged_escalation: bool = False
    """True if any alert involved euid=0 with non-root auid."""


# ── Coverage Summary (for /summary endpoint) ──────────────────────────────────

class TechniqueStatus(BaseModel):
    """Detection status for a single ATT&CK technique."""
    
    technique: ATTCKTechnique
    name: str
    """Human-readable name, e.g. 'Brute Force: Password Guessing'."""
    
    detected: bool
    alert_count: int = 0
    log_source: Optional[LogSource] = None

TECHNIQUE_NAMES: dict[ATTCKTechnique, str] = {
    ATTCKTechnique.T1110_001: "Brute Force: Password Guessing",
    ATTCKTechnique.T1136_001: "Create Local Account",
    ATTCKTechnique.T1003_008: "OS Credential Dumping (/etc/shadow)",
    ATTCKTechnique.T1036:     "Masquerading",
    ATTCKTechnique.T1053_003: "Scheduled Task/Job: Cron",
    ATTCKTechnique.T1078:     "Valid Accounts (No MFA)",
    ATTCKTechnique.T1078_001: "Valid Accounts: Root Login",
    ATTCKTechnique.T1548:     "Abuse Elevation Control",
    ATTCKTechnique.T1562_001: "Impair Defenses: Disable auditd",
    ATTCKTechnique.T1562_002: "Impair Defenses: Disable CloudTrail",
    ATTCKTechnique.T1087_001: "Account Discovery: Local Account",
    ATTCKTechnique.T1082:     "System Information Discovery",
}


class CoverageSummary(BaseModel):
    """ATT&CK coverage summary — what your /summary endpoint returns."""
    
    total_techniques: int
    detected_count: int
    coverage_pct: float = Field(ge=0.0, le=100.0)
    
    techniques: list[TechniqueStatus] = Field(default_factory=list)
    
    total_alerts: int = 0
    critical_count: int = 0
    high_count: int = 0
    
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    @classmethod
    def from_alerts(cls, alerts: list[Alert]) -> "CoverageSummary":
        """Build coverage summary from a list of alerts.
        
        Call this in your report generator instead of computing
        coverage manually in multiple places.
        """
        all_techniques = list(ATTCKTechnique)
        detected_set: set[ATTCKTechnique] = {a.technique for a in alerts}
        
        technique_alert_counts: dict[ATTCKTechnique, int] = {}
        technique_sources: dict[ATTCKTechnique, LogSource] = {}
        for a in alerts:
            technique_alert_counts[a.technique] = technique_alert_counts.get(a.technique, 0) + 1
            technique_sources[a.technique] = a.log_source

        statuses = [
            TechniqueStatus(
                technique=t,
                name=TECHNIQUE_NAMES.get(t, str(t)),
                detected=t in detected_set,
                alert_count=technique_alert_counts.get(t, 0),
                log_source=technique_sources.get(t),
            )
            for t in all_techniques
        ]

        sev_counts = {s: 0 for s in Severity}
        for a in alerts:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1

        return cls(
            total_techniques=len(all_techniques),
            detected_count=len(detected_set),
            coverage_pct=round(len(detected_set) / len(all_techniques) * 100, 1),
            techniques=statuses,
            total_alerts=len(alerts),
            critical_count=sev_counts.get(Severity.CRITICAL, 0),
            high_count=sev_counts.get(Severity.HIGH, 0),
        )


# ── Full Alert Report (for /report endpoint) ──────────────────────────────────

class AlertReport(BaseModel):
    """The complete report object your /report endpoint returns.
    
    Replaces the ad-hoc dict your report_generator.py currently builds.
    """
    
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    
    alerts: list[Alert] = Field(default_factory=list)
    attackers: list[AttackerProfile] = Field(default_factory=list)
    user_activity: list[UserActivity] = Field(default_factory=list)
    coverage: CoverageSummary

    # Pipeline health
    log_lines_processed: dict[str, int] = Field(default_factory=dict)
    """{'auditd': 1240, 'auth_log': 892, 'cloudtrail': 15}"""
    
    parse_errors: int = 0
    """Lines that failed Pydantic validation. Nonzero = investigate."""
    
    pipeline_version: str = "1.0.0"