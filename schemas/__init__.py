"""
schemas/
--------
Pydantic schema layer for the Purple Team Detection Pipeline.

IMPORT FROM HERE, not from submodules:

    from schemas import (
        AuditdEvent, AuthLogEvent, CloudTrailEvent,
        Alert, AlertReport, CoverageSummary,
        LogSource, Severity, ATTCKTechnique,
        parse_raw_log, parse_log_file,
    )
"""

from .base import (
    LogSource,
    Severity,
    ATTCKTechnique,
    AttackSpeed,
    BaseLogEvent,
)
from .auditd import AuditdEvent
from .auth_log import AuthLogEvent
from .cloudtrail import CloudTrailEvent
from .alert import (
    Alert,
    AlertReport,
    AttackerProfile,
    UserActivity,
    CoverageSummary,
    TechniqueStatus,
    TECHNIQUE_NAMES,
)
from .normalizer import (
    LogEvent,
    parse_raw_log,
    parse_log_file,
    parse_cloudtrail_file,
)

__all__ = [
    # Enums
    "LogSource", "Severity", "ATTCKTechnique", "AttackSpeed",
    # Event models
    "BaseLogEvent", "AuditdEvent", "AuthLogEvent", "CloudTrailEvent",
    # Alert models
    "Alert", "AlertReport", "AttackerProfile", "UserActivity",
    "CoverageSummary", "TechniqueStatus", "TECHNIQUE_NAMES",
    # Normalizer
    "LogEvent", "parse_raw_log", "parse_log_file", "parse_cloudtrail_file",
]