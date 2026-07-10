from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

def detect(events: list[AuditdEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if not event.is_privileged_escalation:
            continue

        alerts.append(Alert(
            rule_id     = "rule_005_privilege_escalation",
            technique   = ATTCKTechnique.T1548,
            severity    = Severity.CRITICAL,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            log_source  = LogSource.AUDITD,
            description = (
                f"Privilege escalation detected: "
                f"auid={event.auid} running as euid=0 "
                f"via {event.exe}"
            ),
            extra = {
                "exe":  event.exe,
                "comm": event.comm,
                "auid": event.auid,
                "uid":  event.uid,
                "euid": event.euid,
                "pid":  event.pid,
            }
        ))

    return alerts