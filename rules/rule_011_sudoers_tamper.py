from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

DANGEROUS_FLAGS = {"NOPASSWD", "!tty_tickets", "!authenticate"}

def detect(events: list[AuditdEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if event.key != "sudoers_tamper":
            continue

        # Check if dangerous flags were added
        dangerous_flag_found = None
        for flag in DANGEROUS_FLAGS:
            if flag in (event.raw or ""):
                dangerous_flag_found = flag
                break

        if dangerous_flag_found:
            description = (
                f"Sudoers modified with dangerous flag '{dangerous_flag_found}' "
                f"— authentication bypass possible. "
                f"File: {event.name}, modified by auid={event.auid}"
            )
        else:
            description = (
                f"Sudoers file modified: {event.name} "
                f"by auid={event.auid} euid={event.euid} "
                f"via {event.exe}"
            )

        alerts.append(Alert(
            rule_id     = "rule_011_sudoers_tamper",
            technique   = ATTCKTechnique.T1548,
            severity    = Severity.CRITICAL,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            log_source  = LogSource.AUDITD,
            description = description,
            extra = {
                "exe":                event.exe,
                "comm":               event.comm,
                "auid":               event.auid,
                "euid":               event.euid,
                "file":               event.name,
                "dangerous_flag":     dangerous_flag_found,
            }
        ))

    return alerts