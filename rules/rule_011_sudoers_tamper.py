from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

def detect(events: list[AuditdEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if event.key != "sudoers_tamper":
            continue

        alerts.append(Alert(
            rule_id     = "rule_011_sudoers_tamper",
            technique   = ATTCKTechnique.T1548,
            severity    = Severity.CRITICAL,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            log_source  = LogSource.AUDITD,
            description = (
                f"Sudoers file modified: {event.name} "
                f"by auid={event.auid} euid={event.euid} "
                f"via {event.exe}"
            ),
            extra = {
                "exe":  event.exe,
                "comm": event.comm,
                "auid": event.auid,
                "euid": event.euid,
                "file": event.name,
            }
        ))

    return alerts
